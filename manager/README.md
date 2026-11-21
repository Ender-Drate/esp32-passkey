# TechXPassKey Manager

本地运行的凭据 / 密码管理器，界面按 **apple.com.cn** 的视觉语言重做：
48px 半透明顶部导航、超大标题、大面积留白、发丝线分隔、无卡片无阴影，
颜色只用于链接和唯一的蓝色主操作。结构上参考 `apple-design-skill` 的
克制原则，配色只保留 Apple 的灰阶 + 单一蓝色强调。

## 运行

```powershell
# 在仓库根目录（D:\dsh_Workspaces\ESP32）
.\apps\passkey-manager\start.bat
# 或
.\.venv\Scripts\python.exe .\apps\passkey-manager\server.py
```

服务监听 `http://localhost:8787`，启动后自动打开浏览器。

## 功能

- **概览**：设备连接状态、PIN、凭据数、剩余容量、最近 Passkey、快捷操作。
- **Passkeys**：通过 CTAP 2.1 credentialManagement 读取设备内的常驻凭据，
  支持搜索、复制凭据 ID、删除（设备设置 PIN 时需要 PIN 校验）。
- **密码库**：scrypt（N=2^15）+ AES-256-GCM 加密，文件为
  `data/vault.enc`；支持新增/编辑/删除、密码生成器、TOTP（RFC 6238）、
  Chrome/Edge CSV、Bitwarden JSON/CSV、1Password、KeePass、LastPass 导入，
  以及 Chrome CSV / Bitwarden JSON / KeePass CSV 导出。
- **安全**：设置/修改设备 PIN、触摸确认模式（按键/自动）、USB CDC OTA
  固件更新、恢复出厂（PIN 校验）。
- **演示**：在页面里直接走一次 WebAuthn 注册 + 登录，验证设备签名。

## 架构

```
server.py          HTTP API + 静态文件 + WebAuthn 演示校验
core/vault.py      加密密码库（AES-256-GCM + scrypt）
core/totp.py       TOTP / HOTP
core/importers.py  CSV / JSON 导入导出
web/               Apple 风单页前端（无框架）
```

设备侧通过 `scripts/pkdev.py` 的 CDC 管理协议访问（frame:
`A5 5A | ver | cmd | seq | len | payload | crc16`），PIN 操作与 WebAuthn
测试走同一固件的 CTAP2 分发器；浏览器注册/登录走 Windows 的 FIDO 服务。

## 安全说明

- 服务只监听 `127.0.0.1`，不上传任何数据。
- 主密码只用于派生密钥，不落盘；密码库锁定后内存中的密钥被丢弃。
- 导出文件是明文，请在可信环境使用并及时删除。
- 删除 Passkey / 恢复出厂会要求设备 PIN（若已设置）。
