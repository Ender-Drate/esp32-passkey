# TechXPassKey Android

通过 BLE 管理 TechXPassKey 设备的伴生 App（Android 8.0+）。

## 功能

- 扫描并连接广播 `TechXPassKey` 的设备（FIDO GATT 服务 `0xFFFD`）
- 读取设备信息：固件、AAGUID、PIN 状态、剩余容量、协议
- 设置 / 修改设备 PIN（CTAP2 PIN 协议 2：ECDH P-256 + HKDF + AES-CBC + HMAC）
- 读取并删除常驻凭据（credentialManagement）
- 实时协议日志

## 构建

```bash
cd android
./gradlew assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
```

需要 JDK 17+ 与 Android SDK（compileSdk 37）。`local.properties` 指向本机 SDK。

## 结构

```
app/src/main/java/.../
  MainActivity.java      界面与流程编排
  ble/BleClient.java     GATT 扫描/连接/分帧收发
  ctap/CtapClient.java   getInfo、clientPIN、credentialManagement
  ctap/PinProtocol.java  PIN 协议 2（ECDH/HKDF/AES-CBC/HMAC）
  ctap/Cbor.java         最小 CBOR 编解码（规范 map 排序）
```

## 协议要点

- BLE 请求/响应：`CMD/HLEN/LLEN` 起始帧 + `SEQ/DATA` 续帧，单包 20 字节起。
- CTAP2 CBOR 命令 `0x90`，响应首字节是 CTAP 状态。
- PIN token 权限：凭据管理请求 `cm|lbw`（0x14），并带 `pinUvAuthParam =
  HMAC(token, subCommand || canonical(params))`。
- 设备未设置 PIN 时，credentialManagement 可直接访问；设置后必须提供 PIN。

## 限制

- App 是设备管理器，不是系统 WebAuthn 提供方；浏览器里的 Passkey 仍走
  Windows/Android 系统的 FIDO 栈。
- 未实现 makeCredential/getAssertion 的交互式注册流程（需要按 BOOT 确认，
  适合后续版本加入）。
