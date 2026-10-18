# clash-doctor

Clash for Windows 的**自动诊断与自愈**工具。

专治这一类"看起来在跑、实际全不通"的故障。

---

## 它能修什么

| 故障 | 现象 | 处理方式 |
|---|---|---|
| **profile 字段类型超出内核能力** | `yaml: unmarshal errors: cannot unmarshal !!seq into string` | 重写 DNS 段为兼容版本（必要时整段移除），回写原文件后重新加载 |
| **加载了空配置** | 内核只有端口没有节点，所有请求 `dial failed` | 遍历所有 profile，找到能用的重新激活 |
| **订阅整份失效** | 节点服全挂，TCP 全部拒绝 | 自动切换到其他可用订阅 |
| **分组卡在死节点** | Gemini / 谷歌服务 指着一个超时节点，Google 打不开 | 把指向死节点的分组重设到可用节点 |
| **选点只按延迟** | 延迟低但实际出不了网 | 选中后**真实 HTTPS 验证**，通过才锁定 |

---

## 为什么它比"看起来对"更可靠

这个工具的核心原则只有一条：

> **以 Clash API 返回 204 和真实 HTTPS 出网作为唯一判据。**

不依赖任何"YAML 看起来没问题"的推断，因为：

- **PyYAML 能解析 ≠ Clash 能解析。** 两者对字段类型的宽容度不同。
- `http://www.gstatic.com/generate_204` **不可靠**——国内 CDN 或节点侧会
  直接应答 204，造成假阳性。
- 关闭 TLS 证书校验的探针同样不可靠——伪造响应也能通过。
- 延迟低 ≠ 能出网。URL 测试通过但实际连不出去的节点很常见。

所以本工具：

1. 只探测 **HTTPS** 端点
2. **强制校验 TLS 证书与主机名**（绝不 `CERT_NONE`）
3. 双探针交叉验证（Google 204 + 出口 IP）
4. 选点后必须实测通过才锁定

---

## 用法

```bash
# 诊断 + 自动修复
python clash_doctor.py

# 只诊断，不改任何东西
python clash_doctor.py --check

# 看详细过程
python clash_doctor.py -v

# 指定配置目录（自动探测失败时）
python clash_doctor.py --config-dir "C:\Users\you\.config\clash"
```

**依赖**：Python 3.8+、`pip install pyyaml`

**退出码**：`0` = 健康或修复成功；`1` = 修复失败 / 无可用订阅

---

## 自动发现

脚本会自己找这些东西，通常不需要任何参数：

- 配置目录：`~/.config/clash`、`%APPDATA%\Clash for Windows`（以及 Clash Verge 的路径）
- 控制接口：从 `config.yaml` 读 `external-controller` 和 `secret`
- 混合端口：从 `config.yaml` 读 `mixed-port`

> 注意：控制接口的 secret 是**从本地配置读取**的，脚本本身不含任何密钥，
> 也不含任何订阅链接。可以安全地纳入版本管理。

---

## 定时自愈（可选）

订阅每 24 小时自动更新一次，更新后可能把 profile 覆盖回坏格式。
如果希望自动兜底，可以注册一个计划任务：

```powershell
# 每 30 分钟检查一次，只在不通时才动手
schtasks /create /tn "Clash Doctor" /sc minute /mo 30 ^
  /tr "python \"C:\path\to\clash_doctor.py\"" /f
```

或在 `install_task.ps1` 里改好路径后直接运行。

> 脚本健康时几乎零开销：一次 HTTPS 探测 + 退出。

---

## 它修不了什么

**订阅商停服。** 如果所有 profile 的节点全部失效，脚本只能明确告诉你：

```
所有 profile 均无可用节点。
→ 订阅商可能已停服，需要更换订阅链接。
```

这种情况需要你自己去换订阅，没有技术手段能绕过。

---

## 实现要点

- 用 `http.client` 直连控制端口，**天然绕过系统代理**——
  否则代理挂了时，脚本自己会绕进代理形成死锁。
- `PUT /configs` 的路径必须用**正斜杠**，Windows 反斜杠会被 JSON 转义破坏。
- 修复后的配置会**回写原文件**，保证 Clash GUI 重启后仍然是好的。
- `list.yml` 的 `index` 会被同步修正，避免重启后回到空配置。
- 每次改动前自动备份（`.bak_YYYYmmdd-HHMMSS`）。

---

## 常见坑（踩过记录）

| 坑 | 说明 |
|---|---|
| `cannot unmarshal !!seq into string` | **不是语法问题，是类型问题**。Clash 2023 的 `nameserver-policy` 是 `map[string]string`，只接受单个字符串值；订阅若给成列表 `['a','b']` 就报错。改格式没用，必须改值（降级取第一个，或整段删掉） |
| PyYAML 能解析 ≠ Clash 能解析 | 解析器宽容度不同，要以 API 返回 204 为准 |
| HTTP 探针假阳性 | 必须用 HTTPS + 证书校验 |
| **分流组没切导致假阴性** | `www.google.com` 走 `DOMAIN-KEYWORD,google` → 「谷歌服务」组，**不是**「节点选择」组。只切「节点选择」就测 Google，等于没测到候选节点。必须同步切换承接该流量的组 |
| curl 报 TLS 握手失败但实际是通的 | Windows 的 curl 用 **schannel**，经代理隧道连 google.com 常失败（`schannel: failed to receive handshake`）；同一节点用 OpenSSL（Python/浏览器）却正常。**别拿 curl 当唯一判据**，浏览器和 Python 走的是 OpenSSL/BoringSSL |
| `urllib` 遇中文报错 | Clash 返回的中文 message 会触发 latin-1 编码异常，改用 `http.client` |
| PowerShell 控制台 GBK | 打印 emoji/中文节点名会乱码，设 `PYTHONIOENCODING=utf-8` |
| curl 调本地 API | 必须加 `--noproxy "*"`，否则自己绕进代理 |

---

## License

MIT
