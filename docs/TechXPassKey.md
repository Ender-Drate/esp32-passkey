# TechXPassKey — ESP32 物理 Passkey + 凭据/密码管理器

一块 **ESP32-S3-N16R8** 做成真正的 FIDO2 安全密钥（USB HID + BLE），外加一个
Apple 风的本地管理器（Passkey 列表 / 删除 / PIN / OTA / 加密密码库 / TOTP /
WebAuthn 演示）。

![概览](screenshots/overview.png)

## 快速开始

```powershell
# 1) 打开管理器（会自动打开 http://localhost:8787）
python manager/server.py

# 2) 固件（已烧录；改动后重新烧）
pio run -d firmware -t upload --upload-port COM8
```

- 设备通过 **CH343 UART（COM8）** 烧录，通过 **原生 USB（CDC + HID）** 工作。
- 浏览器注册：管理器「演示」页 → 注册 Passkey → 选择 **TechXPassKey** →
  按一下板子上的 **BOOT**。
- 设备 PIN：在管理器「安全」页设置（初始未设置）。删除 Passkey、恢复出厂
  会要求 PIN。

## 已经验证的能力

| 能力 | 验证方式 |
|---|---|
| Chrome/Windows WebAuthn 注册 + 登录 | 现场实测（attestation=none，flags 0x45/0x5） |
| CTAP2.1 makeCredential / getAssertion | python-fido2 + 签名校验 |
| CTAP1/U2F register / authenticate | 签名 + 计数器校验 |
| clientPIN 协议 1 & 2 | setPIN / changePIN / getToken |
| credentialManagement | 枚举 RP/凭据、删除、元数据 |
| largeBlobs | 写入 → 读回 → 哈希校验 |
| authenticatorConfig | alwaysUv / minPINLength |
| OTA（USB CDC） | 436 KB 固件写入 + 重启 + 数据保留 |
| 断电保存 | 重启后 PIN/凭据/计数器仍在 |
| BLE CTAP | bleak：getInfo + PIN + makeCredential + getAssertion 全通过 |

## 目录

```
firmware/            固件（Arduino + TinyUSB + Bluedroid）
manager/        管理器（Python 后端 + Apple 风 Web UI）
  server.py                  HTTP API / 静态文件 / WebAuthn 校验
  core/vault.py              scrypt + AES-256-GCM 密码库
  core/totp.py               TOTP/HOTP
  core/importers.py          CSV/JSON 导入导出
  web/                       前端（无框架）
scripts/pkdev.py             设备管理协议客户端（INFO/OTA/凭据/PIN…）
scripts/flash_passkey.ps1    只接原生 USB 时的烧录脚本（BOOT+RST）
tests/                       ctap_test / protocols_test / pin_persist / ble_ctap_test
docs/screenshots/            UI 截图
```

## 界面

| Passkeys | 密码库 | 安全 |
|---|---|---|
| ![](screenshots/passkeys.png) | ![](screenshots/vault.png) | ![](screenshots/security.png) |

设计：按 **apple.com.cn** 的视觉语言——48px 半透明顶部导航、超大标题、
大面积留白、发丝线分隔、无卡片无阴影，颜色只保留灰阶与单一蓝色强调；
结构上沿用 apple-design-skill 的克制原则，去掉了深色侧栏、卡片和渐变。

## 协议细节

- **USB**：复合设备，HID（usage page `0xF1D0`，64 字节报告，CTAPHID）+
  CDC（管理帧 `A5 5A | ver | cmd | seq | len | payload | crc16`）。
- **CTAP2.1**：getInfo / makeCredential / getAssertion / getNextAssertion /
  clientPIN / reset / credentialManagement / selection / largeBlobs / config。
- **CTAP1**：U2F 原始 APDU（短/扩展长度），attestation 证书内嵌。
- **BLE**：FIDO GATT `0xFFFD`，`CMD/HLEN/LLEN` + `SEQ` 分帧，CBOR `0x90` /
  MSG `0x83` / PING `0x81` / KEEPALIVE `0x82`。
- **存储**：NVS（主密钥、PIN 哈希、设置、计数），LittleFS（`/creds.bin`、
  `/blob.bin`），双 3 MB OTA 槽。

## 测试

```powershell
python tests/ctap_test.py        # PIN + 注册 + 断言（CDC）
python tests/protocols_test.py   # U2F + credMgmt + largeBlob
python tests/pin_persist.py      # 重启后 PIN/凭据保留
python tests/ble_ctap_test.py    # BLE（需 -DPK_BLE_ALIAS=1 构建）
```

## 安全模型

- 设备端：主密钥在 NVS；PIN 只存 `AES-GCM(masterKey, SHA256(pin)[:16])`；
  凭据私钥只在 flash / RAM 中出现；non-resident 凭据用 AES-GCM 包裹。
- 管理器：密码库 `scrypt(N=2^15) + AES-256-GCM`，主密码不落盘；只监听
  `127.0.0.1`；导出为明文，需自行保管。
- 触摸确认：BOOT 键；管理器可切「自动确认」但仅建议测试时使用。

## 已知限制

- 未实现 `hmac-secret` / `credBlob` / `largeBlobKey`（未广告）。
- `credProtect` 只接受输入、不回显（Windows 解析兼容问题）。
- Windows 的 FIDO 栈独占 BLE `0xFFFD`：Windows 浏览器正常，但通用 GATT
  工具看不到它；BLE 自动化测试用 `-DPK_BLE_ALIAS=1` 映射到 `0xFFF0`。
- 首次烧录若只接原生 USB：按住 BOOT → 点 RST → 松开，再
  `.\scripts\flash_passkey.ps1`。

## Android App

`android/` 是 BLE 伴生 App（Java，Android 8+）：

- 扫描连接 `TechXPassKey`（FIDO GATT `0xFFFD`）
- 设备信息、PIN 设置/修改、凭据列表与删除、协议日志
- PIN 协议 2：ECDH P-256 + HKDF-SHA-256 + AES-256-CBC + HMAC-SHA-256

构建：

```bash
cd android
./gradlew assembleDebug
```

APK 也会随 GitHub Release 提供。