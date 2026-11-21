# TechXPassKey 固件（ESP32-S3）

一块 ESP32-S3-N16R8 做的 FIDO2 / CTAP 2.1 / U2F 认证器，USB 复合设备：
HID（CTAPHID）+ CDC（管理协议 / OTA）。

## 功能

| 能力 | 状态 |
|---|---|
| CTAP2.1 makeCredential / getAssertion | ✅ 浏览器实测通过 |
| CTAP1 / U2F register / authenticate / version | ✅ 签名校验通过 |
| clientPIN 协议 1 & 2（set / change / getToken） | ✅ |
| 常驻凭据（Passkey）+ 计数 | ✅ |
| credentialManagement（枚举 RP/凭据、删除、改用户） | ✅ |
| largeBlobs（读 / 写 / 哈希校验） | ✅ |
| authenticatorConfig（alwaysUv / minPINLength） | ✅ |
| OTA（USB CDC 写入 + 重启） | ✅ |
| 断电保存 PIN / 凭据 / 计数器 | ✅ |
| BLE 传输（GATT 0xFFFD，FIDO 分帧） | ✅ `tests/ble_ctap_test.py` |

## 编译 / 烧录

```powershell
# 编译
.\scripts\pio.ps1 run -d .\projects\passkey

# 通过 CH343 UART 口烧录（推荐，自动复位）
.\scripts\pio.ps1 run -d .\projects\passkey -t upload --upload-port COM8

# 只接了原生 USB 时：按住 BOOT → 点 RST → 松开，再
.\scripts\flash_passkey.ps1
```

首次烧录后，后续可以直接在管理器里 OTA，或 `python scripts/pkdev.py ota <firmware.bin>`。

## 硬件约定

- 板载 **BOOT（GPIO0）** = 触摸确认键。
- 板载 RGB LED（GPIO48，视板子而定）指示状态：蓝=等待触摸，绿=成功，红=错误。
- 原生 USB 口（VID 303A / PID 82F1，产品名 `TechXPassKey`）跑 HID + CDC；
  CH343 UART 口用于烧录/日志。

## 存储

- `nvs`：主密钥、PIN 哈希（AES-GCM 加密）、设置、启动计数，以及**被 KEK 包裹的
  DEK**（`dek`）。主板不保存 KEK。
- LittleFS `spiffs` 分区：`/creds.bin` 是 **PKC2 密文**（AES-256-GCM，密钥为 DEK），
  不是明文私钥；`/blob.bin` 也是 **PKB1 密文**（同一个 DEK）。
- 开机流程：副板证明 link key → 副板用 link key 加密把 **KEK** 发给主板 → 主板用
  KEK 解开 NVS 里的 DEK → 用 DEK 把 `/creds.bin` 解密到 RAM。没有副板时主板上只有
  密文和被包裹的 DEK，无法得到私钥。
- **副板断开 2.5 秒后，主板清空 RAM 中的 DEK/KEK 和凭据**；重新接上副板会再次
  走 KEK 流程解密。PIN 最短长度提高到 **6 位**（已有 PIN 继续有效，修改/新设需 ≥6）。
- 分区表：两个 3 MB OTA 槽 + ~9.9 MB 数据分区（`partitions.csv`）。

## 调试

固件默认关闭逐包日志。需要抓 CTAPHID/CTAP 细节时：

```powershell
# platformio.ini build_flags 里加 -DPK_DEBUG=1 后重新编译
python scripts/pkdev.py logs
```

## BLE

固件同时作为 FIDO BLE 认证器广播：

- Service `0000FFFD-0000-1000-8000-00805F9B34FB`
- `F1D0FFF1…` 控制点（write）、`F1D0FFF2…` 状态（notify）、
  `F1D0FFF3…` 控制点长度、`0x2A28` 服务版本、`F1D0FFF4…` 版本位域
- 请求/响应按 FIDO BLE 规范分帧：`CMD/HLEN/LLEN` 起始帧 + `SEQ/DATA` 续帧，
  支持 CTAP2 CBOR（0x90）与 U2F MSG（0x83）

验证方式：

```powershell
# Windows 的 FIDO 栈会独占 0xFFFD，测试构建把它映射到 0xFFF0
$env:PLATFORMIO_BUILD_FLAGS='-DPK_BLE_ALIAS=1'
.\scripts\pio.ps1 run -d .\projects\passkey -t upload --upload-port COM8
python tests/ble_ctap_test.py     # PIN + makeCredential + getAssertion 全通过
```

正式固件默认使用标准 `0xFFFD`；Android 等使用标准 GATT 的客户端可直接发现。

## 第二块板（物理互锁）

主板 GPIO16/17 与副板 GPIO41/42 两线 UART 相连，副板保存 32 字节 link key；
主板只有在持续收到副板的 HMAC 证明时才允许注册/登录。

```
主板 GPIO16 (TX) ──→ 副板 GPIO42 (RX)
主板 GPIO17 (RX) ←── 副板 GPIO41 (TX)
GND ─────────────── GND
```

- 也支持直连接法（`16→41`、`17→42`）：固件每 6 秒自动交换 RX/TX，直到收到证明。
- 上电自动配对：主板生成 key，发给空副板；副板回 `OK K` 后开始应答 nonce。
- **配对是一次性的**：第一次成功证明后，主板把 `paired` 写入 NVS，之后**不再
  静默分发 `K`**。换副板必须走「更换副板」流程：旧副板先证明在场 → 主板生成
  pending key → 新副板保存并证明 → **把 DEK 重新用新 KEK 包裹** → 原子切换。
  **不删除 Passkey**；超时/取消则保留旧 key 和旧包裹，旧副板继续可用。
- **KEK 只在副板**：主板 NVS 只有 `AES-GCM(KEK, DEK)`；更换副板只重新包裹 DEK，
  不重新加密整个凭据库。
- 管理器「重置配对」：清除两块板的 link key，**保留副板 KEK 和 Passkey**，随后自动
  重新配对；「彻底清除」：清除副板 link key + KEK，并同时恢复出厂主板（Passkey 删除）。
  两者都需要设备 PIN。
- 运行时每 700 ms 一次 challenge；2.5 s 没有有效应答 → 红灯 + 拒绝
  `makeCredential` / `getAssertion` / U2F（`0x27 OPERATION_DENIED`）。
- **PIN 仍然存在主板**，由电脑端输入；副板只是额外的物理因子，不保存 PIN。
- 恢复出厂（触摸确认）会清除凭据和 link key，之后可重新配对新副板。
- 编译时加 `-DPK_INTERLOCK=0` 可关闭互锁（仅用于对比测试）。

副板固件在 `../passkey-key`，接线、配对、清 key 见该目录 README。

## 已知限制

- 未实现 `hmac-secret` / `credBlob` / `largeBlobKey` 扩展（未在 getInfo 广告）。
- `credProtect` 只接受输入、不回显输出（Windows/Chrome 对回显的解析有兼容问题）。
- Windows 的 FIDO 栈会独占 `0xFFFD` 服务：Windows 上浏览器/Windows Hello 正常，
  但通用的 BLE GATT 工具看不到该服务；BLE 自动化测试需用 `-DPK_BLE_ALIAS=1`
  映射到 `0xFFF0`。
