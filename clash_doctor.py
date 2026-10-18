#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clash-doctor — Clash for Windows 自动诊断与自愈

解决的问题
----------
1. 订阅自动更新后 profile 的 DNS 段语法超出内核能力
   -> 报 "yaml: unmarshal errors: cannot unmarshal !!seq into string"
   -> 自动重写为兼容 DNS 段后重新加载
2. list.yml 的 index: -1，内核加载空配置（只有端口没有节点）
   -> 自动寻找可用 profile 并激活
3. 当前订阅全部节点失效
   -> 遍历所有 profile，逐个探测，报告哪个还能用
4. 分组指向已死节点（如 Gemini 组卡在超时的新加坡节点）
   -> 自动把指向死节点的分组重设到该组池内可用的最快节点

核心原则
--------
以 Clash API 返回 204 (配置加载成功) 和真实连通性作为唯一判据，
不依赖任何"看起来正确"的 YAML 推断。

用法
----
    python clash_doctor.py            # 诊断 + 自动修复
    python clash_doctor.py --check    # 只诊断，不改动
    python clash_doctor.py --verbose

退出码
------
    0 = 链路健康（或修复成功）
    1 = 修复失败 / 无可用订阅
"""

import argparse
import http.client
import json
import os
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[FATAL] 需要 PyYAML: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------- 常量

# 必须是 HTTPS：HTTP 的 generate_204 会被国内 CDN / 节点侧直接应答，
# 导致"假阳性"——探针说通了，实际出不了网。
# 多探针 + 强制证书校验，才是真实出网证据。
PROBES = [
    ("https://www.google.com/generate_204", 204),
    ("https://api.ipify.org?format=json", 200),
]
PROBE_URL = PROBES[0][0]  # 供节点 delay 测试使用

# Clash 2023 内核能接受的 DNS 键（新语法键会被剔除）
DNS_SAFE_KEYS = {
    "enable", "listen", "ipv6", "use-hosts", "use-system-hosts",
    "enhanced-mode", "fake-ip-range", "fake-ip-filter",
    "default-nameserver", "nameserver", "fallback",
    "fallback-filter", "nameserver-policy", "proxy-server-nameserver",
    "respect-rules", "cache-algorithm",
}

SAFE_NAMESERVERS = ["223.5.5.5", "119.29.29.29", "114.114.114.114"]
SAFE_FALLBACK = ["8.8.8.8", "1.1.1.1"]

GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}
REAL_NODE_EXCLUDE = GROUP_TYPES | {"Direct", "Reject", "Compatible", "Pass"}

V = False  # verbose


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{ts} [{level}] {msg}")


def vlog(msg):
    if V:
        log(msg, "DEBUG")


def die(msg):
    log(msg, "ERROR")
    return 1


class ClashError(Exception):
    """Clash API 返回 >=400 时抛出。"""

    def __init__(self, status, message):
        self.status = status
        self.message = message
        super().__init__(f"HTTP {status}: {message}")


# ---------------------------------------------------------------- 路径发现

def find_config_dir(explicit=None):
    """定位 Clash for Windows 的配置目录。"""
    if explicit:
        p = Path(explicit)
        if p.is_dir():
            return p
        raise SystemExit(f"指定目录不存在: {explicit}")

    home = Path.home()
    candidates = [
        home / ".config" / "clash",
        home / "AppData" / "Roaming" / "Clash for Windows",
        home / "AppData" / "Roaming" / "io.github.clash-verge-rev.clash-verge-rev",
        home / "AppData" / "Roaming" / "clash-verge",
        home / ".config" / "clash-verge",
    ]
    for c in candidates:
        if (c / "config.yaml").is_file():
            return c

    # 兜底：扫盘找 config.yaml + profiles/
    for drive in ("C:", "D:", "E:"):
        base = Path(drive + "\\")
        if not base.exists():
            continue
        for pat in ("**/.config/clash", "**/Clash for Windows"):
            try:
                for c in base.glob(pat):
                    if (c / "config.yaml").is_file():
                        return c
            except (PermissionError, OSError):
                continue
    raise SystemExit("找不到 Clash 配置目录，请用 --config-dir 指定")


def read_controller(conf_dir):
    """从 config.yaml 读取 external-controller / secret / mixed-port。"""
    cfg_path = conf_dir / "config.yaml"
    txt = cfg_path.read_text(encoding="utf-8", errors="replace")
    try:
        d = yaml.safe_load(txt) or {}
    except Exception:
        # config.yaml 理论上非常简单，退化为逐行解析
        d = {}
        for line in txt.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                d[k.strip()] = v.strip()

    controller = str(d.get("external-controller") or "").strip()
    secret = str(d.get("secret") or "").strip()
    mixed = d.get("mixed-port") or d.get("port") or 7890

    if not controller:
        controller = "127.0.0.1:9090"
    if not controller.startswith(("http://", "https://")):
        controller = "http://" + controller

    return controller.rstrip("/"), secret, int(mixed)


# ---------------------------------------------------------------- Clash API

class Clash:
    def __init__(self, base, secret):
        self.base = base
        self.secret = secret
        # 用 http.client 直连控制器：
        # 1. 天然绕过系统代理，避免代理挂了时自锁死循环
        # 2. 避开 urllib 对非 latin-1 响应内容的编码崩溃
        u = urllib.parse.urlparse(base)
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 9090
        self.scheme = u.scheme or "http"

    def _req(self, path, method="GET", body=None, timeout=30):
        headers = {}
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if self.scheme == "https":
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)

        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()

        data = None
        if raw.strip():
            try:
                data = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                data = raw.decode("utf-8", errors="replace")

        if status >= 400:
            msg = data.get("message", "") if isinstance(data, dict) else str(data)
            raise ClashError(status, msg)
        return status, data

    def version(self):
        return self._req("/version", timeout=8)[1]

    def configs(self):
        return self._req("/configs", timeout=8)[1]

    def proxies(self):
        return self._req("/proxies", timeout=15)[1]["proxies"]

    def set_mode(self, mode):
        self._req("/configs", "PATCH", {"mode": mode})

    def load_config(self, path):
        """PUT /configs 加载 profile。返回 (ok, message)。"""
        fwd = str(Path(path)).replace("\\", "/")
        try:
            status, _ = self._req(
                "/configs?force=true", "PUT", {"path": fwd}, timeout=90
            )
            return (status in (200, 204)), f"HTTP {status}"
        except ClashError as e:
            return False, e.message or f"HTTP {e.status}"
        except Exception as e:
            return False, str(e)

    def delay(self, name, timeout=5000):
        """测单个节点的延迟，失败返回 None。"""
        q = urllib.parse.quote(name, safe="")
        path = f"/proxies/{q}/delay?timeout={timeout}&url={urllib.parse.quote(PROBE_URL, safe='')}"
        try:
            status, d = self._req(path, timeout=(timeout / 1000) + 8)
            if status == 200 and d and d.get("delay", 0) > 0:
                return d["delay"]
        except (ClashError, Exception):
            pass
        return None

    def select(self, group, node):
        q = urllib.parse.quote(group, safe="")
        try:
            self._req(f"/proxies/{q}", "PUT", {"name": node}, timeout=20)
            return True
        except Exception as e:
            vlog(f"select {group} -> {node} 失败: {e}")
            return False


# ---------------------------------------------------------------- 连通性

def probe_direct(proxy_port, url, expect, timeout=15):
    """通过 127.0.0.1:mixed-port 发起真实请求。

    强制 TLS 证书校验：只有证书链与主机名都对得上，才说明真的连到了目标站，
    而不是被节点或本地中间设备伪造的响应。
    """
    # 默认 context = 校验证书 + 校验主机名。绝不关闭。
    ctx = ssl.create_default_context()

    handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
    )
    opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=ctx))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "clash-doctor/1.1"})
        with opener.open(req, timeout=timeout) as r:
            return r.status == expect, r.status
    except urllib.error.HTTPError as e:
        # 有响应但状态码不符：仍算"出网可达"，只是不是期望值
        return False, e.code
    except Exception as e:
        vlog(f"probe {url} 异常: {type(e).__name__}: {e}")
        return False, None


def link_healthy(mixed_port, require_all=False):
    """真实出网判定。默认任一个强探针通过即健康。"""
    results = []
    for url, expect in PROBES:
        ok, code = probe_direct(mixed_port, url, expect)
        results.append((url, ok, code))
        if ok and not require_all:
            return True, code
    for url, ok, code in results:
        vlog(f"  probe {url} -> ok={ok} code={code}")
    passed = all(r[1] for r in results)
    return passed, next((c for _, ok, c in results if ok), None)


# ---------------------------------------------------------------- YAML 修复

def yaml_parses(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = yaml.safe_load(f)
        return isinstance(d, dict) and bool(d.get("proxies"))
    except Exception as e:
        vlog(f"{path.name} YAML 解析失败: {e}")
        return False


def sanitize_dns(d):
    """把 DNS 段改写成 2023 内核能吃的基础版。"""
    dns = d.get("dns")
    if not isinstance(dns, dict):
        dns = {}

    clean = {k: v for k, v in dns.items() if k in DNS_SAFE_KEYS}

    # 强制基础可达的 DNS，避免自定义 DoH 在新内核下解析不出来
    clean["enable"] = True
    clean["listen"] = clean.get("listen") or "127.0.0.1:1053"
    clean["ipv6"] = False
    clean["default-nameserver"] = ["223.5.5.5", "119.29.29.29"]
    clean["enhanced-mode"] = "fake-ip"
    clean["fake-ip-range"] = "198.18.0.1/16"
    clean["nameserver"] = list(SAFE_NAMESERVERS)
    clean["fallback"] = list(SAFE_FALLBACK)
    clean["fallback-filter"] = {"geoip": True, "geoip-code": "CN"}

    # --- 关键坑 ---
    # Clash 2023.08 内核的 nameserver-policy 是 map[string]string，
    # 只接受"单个字符串"作为值。订阅若给成列表 ['a','b']，就会报：
    #     yaml: unmarshal errors: cannot unmarshal !!seq into string
    # 这不是"内联语法"问题，是值的类型问题——改格式没用，必须改值。
    #
    # 处理策略：值若是列表，降级取第一个；仍不是字符串则整段删除。
    # 由于 nameserver 已换成国内可达的 223.5.5.5 / 119.29.29.29，
    # 节点域名本身能正常解析，删掉 policy 不影响出网。
    policy = clean.get("nameserver-policy")
    if isinstance(policy, dict):
        fixed_policy = {}
        for k, v in policy.items():
            if isinstance(v, list) and v:
                v = v[0]
            if isinstance(v, str) and v:
                fixed_policy[str(k)] = v
        if fixed_policy:
            clean["nameserver-policy"] = fixed_policy
            vlog(f"  nameserver-policy 降级为字符串值: {list(fixed_policy)[:3]}")
        else:
            clean.pop("nameserver-policy", None)
    elif policy is not None:
        clean.pop("nameserver-policy", None)

    # 移除 fake-ip-filter 里可能引起问题的超长列表？保留，内核支持
    d["dns"] = clean
    return d


def repair_profile(src: Path, level=1) -> Path:
    """生成一个内核兼容版本的 profile。返回修复后的路径。

    level=1: 重写 DNS 段为兼容版本
    level=2: 直接移除整个 dns 段，让内核用默认设置（最激进但最稳）
    """
    with open(src, encoding="utf-8") as f:
        d = yaml.safe_load(f)

    if level >= 2:
        d.pop("dns", None)
        vlog("  已移除整个 dns 段")
    else:
        d = sanitize_dns(d)

    # 顶层也剔除旧内核不认识的新键（可能导致 unmarshal 失败）
    SAFE_TOP = {
        "port", "socks-port", "redir-port", "tproxy-port", "mixed-port",
        "allow-lan", "bind-address", "mode", "log-level", "ipv6", "udp",
        "external-controller", "secret", "authentication",
        "proxies", "proxy-providers", "proxy-groups", "rules",
        "rule-providers", "dns", "hosts", "tun", "sniffer",
        "profile", "experimental", "geodata-mode", "geo-auto-update",
        "unified-delay", "tcp-concurrent", "global-client-fingerprint",
        "find-process-mode", "interface-name", "routing-mark",
        "cfw-latency-timeout", "cfw-conn-break-strategy",
    }
    dropped = [k for k in list(d.keys()) if k not in SAFE_TOP]
    for k in dropped:
        d.pop(k, None)
    if dropped:
        vlog(f"  剔除顶层未知键: {dropped}")

    suffix = "_fixed.yml" if level < 2 else "_fixed_nodns.yml"
    out = src.with_name(src.stem + suffix)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(
            d, f, allow_unicode=True, sort_keys=False,
            default_flow_style=False, width=10**6,
        )
    return out


def activate(clash: Clash, path: Path):
    """尝试加载 profile，失败则修复后重试。返回 (ok, 实际加载路径)。"""
    ok, msg = clash.load_config(path)
    if ok:
        return True, path

    log(f"  直接加载失败: {msg[:160]}", "WARN")

    if not yaml_parses(path):
        log("  YAML 本身不可解析，放弃", "WARN")
        return False, None

    last_msg = msg
    for level, desc in ((1, "重写 DNS 段为兼容版本"), (2, "移除整个 dns 段")):
        log(f"  修复 L{level}: {desc} ...")
        try:
            fixed = repair_profile(path, level=level)
        except Exception as e:
            log(f"    修复失败: {e}", "WARN")
            continue

        ok, msg = clash.load_config(fixed)
        if ok:
            log(f"  ✓ L{level} 修复版加载成功 -> {fixed.name}")
            # 回写原文件，保证 Clash GUI 重启后仍是好的
            try:
                shutil.copyfile(fixed, path)
                log(f"  ✓ 已回写 {path.name}")
            except Exception as e:
                vlog(f"回写失败: {e}")
            return True, fixed

        last_msg = msg
        log(f"    L{level} 仍失败: {msg[:140]}", "WARN")

    log(f"  全部修复手段失败", "WARN")
    return False, None


# ---------------------------------------------------------------- 诊断与自愈

def enumerate_profiles(conf_dir):
    """按 list.yml 顺序返回 (index, name, path)。"""
    pdir = conf_dir / "profiles"
    lfile = pdir / "list.yml"

    entries = []
    if lfile.is_file():
        try:
            lst = yaml.safe_load(lfile.read_text(encoding="utf-8")) or {}
            for i, item in enumerate(lst.get("files") or []):
                fn = item.get("time")
                if not fn:
                    continue
                p = pdir / str(fn)
                if p.is_file():
                    entries.append((i, str(item.get("name") or p.stem), p))
        except Exception as e:
            vlog(f"list.yml 解析失败: {e}")

    known = {p.resolve() for _, _, p in entries}
    for p in sorted(pdir.glob("*.yml")):
        if p.name in ("list.yml",) or p.name.endswith("_fixed.yml"):
            continue
        if p.resolve() not in known:
            entries.append((len(entries), p.stem, p))

    return entries, lfile


def measure_all(clash: Clash, timeout=5000):
    """测所有真实节点延迟，返回 {name: delay|None}。"""
    proxies = clash.proxies()
    nodes = {n: v for n, v in proxies.items() if v.get("type") not in REAL_NODE_EXCLUDE}
    log(f"  待测节点 {len(nodes)} 个 ...")

    result = {}
    for i, n in enumerate(nodes, 1):
        d = clash.delay(n, timeout=timeout)
        result[n] = d
        mark = "✓" if d else "✗"
        vlog(f"    [{i}/{len(nodes)}] {mark} {n} = {d if d else 'timeout'}")
    alive = sum(1 for d in result.values() if d)
    log(f"  可用节点 {alive}/{len(nodes)}")
    return result


MAIN_GROUPS = ("节点选择", "Proxy", "PROXY")


def dead_groups(clash: Clash, delays):
    """返回当前指向死节点的 Selector 分组列表。"""
    proxies = clash.proxies()
    out = []
    for gname, g in proxies.items():
        if g.get("type") not in GROUP_TYPES:
            continue
        now = g.get("now")
        if now and now in delays and delays[now] is None:
            out.append(gname)
    return out


def apply_node(clash: Clash, node, groups):
    """把 node 应用到指定分组（池里有才设）。"""
    proxies = clash.proxies()
    done = []
    for gname in groups:
        g = proxies.get(gname)
        if not g or g.get("type") not in GROUP_TYPES:
            continue
        if node not in (g.get("all") or []):
            continue
        if clash.select(gname, node):
            done.append(gname)
    return done


def pick_and_verify(clash: Clash, delays, mixed_port, max_try=4):
    """按延迟排序逐个候选，选中后真实出网验证，通过才锁定。

    仅按延迟选点是不可靠的：延迟低 ≠ 能出网。
    必须以真实 HTTPS 请求成功作为唯一判据。
    """
    alive = sorted(
        ((n, d) for n, d in delays.items() if d), key=lambda x: x[1]
    )
    if not alive:
        log("  没有可用节点", "ERROR")
        return None

    proxies = clash.proxies()
    dg = dead_groups(clash, delays)

    # 分组优先级：主选择组 + 已死的组 + 常见服务组
    targets = list(MAIN_GROUPS)
    for g in dg:
        if g not in targets:
            targets.append(g)
    for g in ("谷歌服务", "Gemini", "GLOBAL"):
        if g not in targets:
            targets.append(g)

    for node, delay in alive[:max_try]:
        log(f"  尝试 {node} ({delay}ms) ...")
        applied = apply_node(clash, node, targets)
        if not applied:
            log(f"    该节点不在任何目标分组池内，跳过", "WARN")
            continue
        vlog(f"    应用到: {applied}")

        time.sleep(0.6)
        ok, code = link_healthy(mixed_port, require_all=False)
        if ok:
            log(f"    ✓ 出网验证通过 (code={code})")
            log(f"  ✓ 锁定节点: {node} ({delay}ms) -> {applied}")
            return node
        log(f"    ✗ 出网失败 (code={code})，换下一个", "WARN")

    log("  所有候选节点均无法真实出网", "ERROR")
    return None


def write_index(list_file: Path, idx: int):
    if not list_file.is_file():
        return
    txt = list_file.read_text(encoding="utf-8")
    import re
    new, n = re.subn(r"(?m)^index:\s*-?\d+\s*$", f"index: {idx}", txt)
    if n and new != txt:
        backup = list_file.with_suffix(f".yml.bak_{datetime.now():%Y%m%d-%H%M%S}")
        shutil.copyfile(list_file, backup)
        list_file.write_text(new, encoding="utf-8", newline="\n")
        log(f"  ✓ list.yml index -> {idx}（备份 {backup.name}）")


def main():
    global V
    ap = argparse.ArgumentParser(description="Clash for Windows 自动诊断与自愈")
    ap.add_argument("--config-dir", help="Clash 配置目录")
    ap.add_argument("--check", action="store_true", help="只诊断，不修改")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--timeout", type=int, default=5000, help="节点测活超时 ms")
    args = ap.parse_args()
    V = args.verbose

    log("=" * 56)
    log("clash-doctor — Clash 诊断与自愈")
    log("=" * 56)

    conf_dir = find_config_dir(args.config_dir)
    controller, secret, mixed_port = read_controller(conf_dir)
    log(f"配置目录 : {conf_dir}")
    log(f"控制接口 : {controller}")
    log(f"混合端口 : {mixed_port}")

    clash = Clash(controller, secret)

    # --- 1. 内核存活
    try:
        ver = clash.version()
        log(f"内核版本 : {ver.get('version')} (premium={ver.get('premium')})")
    except Exception as e:
        return die(f"控制接口连不上: {e}\n提示：Clash 是否在运行？")

    # --- 2. 当前链路
    ok, code = link_healthy(mixed_port)
    log(f"当前链路 : {'✓ 健康' if ok else '✗ 不通'} (code={code})")
    if ok:
        log("无需修复。")
        return 0

    if args.check:
        log("--check 模式，仅报告不修改。")
        return 0 if ok else 1

    # --- 3. 找可用 profile
    entries, lfile = enumerate_profiles(conf_dir)
    if not entries:
        return die("找不到任何 profile")

    log(f"发现 {len(entries)} 个 profile，逐个尝试 ...")

    active = None
    delays = {}
    order = sorted(entries, key=lambda e: (e[0] != 2, e[0]))  # 优先当前订阅

    for idx, name, path in order:
        log(f"[{idx}] {name} — {path.name}")
        good, used = activate(clash, path)
        if not good:
            continue

        delays = measure_all(clash, timeout=args.timeout)
        if not any(delays.values()):
            log(f"  ✗ 该订阅全部节点失效", "WARN")
            continue

        active = (idx, name, path, used)
        break

    if not active:
        return die("所有 profile 均无可用节点。\n"
                   "→ 订阅商可能已停服，需要更换订阅链接。")

    idx, name, path, used = active
    log(f"选用 : [{idx}] {name}")

    # --- 4. 选点（选中即验证，通过才锁定）
    try:
        clash.set_mode("rule")
        log("✓ 模式 -> rule")
    except Exception as e:
        vlog(f"设置模式失败: {e}")

    log("选点并验证真实出网 ...")
    chosen = pick_and_verify(clash, delays, mixed_port)
    if not chosen:
        log("配置已加载，但没有任何节点能真实出网", "ERROR")
        log("→ 订阅已失效，需要更换订阅链接", "ERROR")
        return 1

    # --- 5. 固化
    write_index(lfile, idx)

    # --- 6. 最终复验（双探针）
    time.sleep(2)
    ok, code = link_healthy(mixed_port, require_all=True)
    log("=" * 56)
    if ok:
        log(f"✓ 修复成功，双探针均通过 (code={code})")
        alive = sum(1 for d in delays.values() if d)
        log(f"  节点 {alive}/{len(delays)} 可用 | 出口: {chosen}")
        return 0
    else:
        log("✗ 单探针通过但双探针未全通过", "ERROR")
        log("  可能原因：节点限流 / 部分站点被阻断")
        return 1


if __name__ == "__main__":
    sys.exit(main())
