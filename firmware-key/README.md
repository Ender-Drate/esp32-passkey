# TechXPassKey Key Board

第二块 ESP32（副板），用来保存解锁主板的 link key，并通过两线 UART 向主板证明
"我在场"。没有它，主板会拒绝 makeCredential / getAssertion / U2F，并亮红灯。

## 接线

```
主板 GPIO16 (TX) ──→ 副板 GPIO42 (RX)     ← 推荐
主板 GPIO17 (RX) ←── 副板 GPIO41 (TX)
GND ─────────────── GND
```

也支持直连接法（`16→41`、`17→42`）：主板固件会在 6 秒内自动交换 RX/TX 引脚，
两种接法都能配对。推荐仍然按 TX→RX 交叉接。

两块板可以各自 USB 供电（同一拓展坞即可），但 GND 必须共地。

## 烧录

```bash
pio run -d firmware-key
pio run -d firmware-key -t upload --upload-port COM11
```

副板的 CH343 是 UART0，烧录和日志都走它；不需要原生 USB。
## KEK（解锁主板的密钥）

副板除了 link key，还保存一把 32 字节 **KEK**（NVS `kek`）。主板不保存 KEK：
它只保存 `AES-GCM(KEK, DEK)` 和用 DEK 加密的凭据库。

开机流程：

1. 主板发 `C <nonce>`，副板用 link key 回 HMAC 证明。
2. 证明通过后主板发 `E <nonce>`，副板用 link key 把 **KEK** 做 AES-256-GCM 加密，
   回 `E <iv||ct||tag>`。
3. 主板解出 KEK，解开 NVS 里的 DEK，再用 DEK 解密 `/creds.bin` 到 RAM。
4. 没有副板时，主板上只有密文和被包裹的 DEK，无法得到 Passkey 私钥。

## 配对

1. 主板和副板都上电，接好线。
2. 主板检测到副板没有 key 时，会通过 UART 发送 `K <64 hex>`。
3. 副板保存 key，回 `OK K`；之后每 700 ms 用 HMAC-SHA256 应答主板的 nonce。
4. 主板日志出现 `second board stored the link key` 和 `second board OK`，LED 转蓝，
   管理器「安全 → 第二块板」显示已连接。

**配对是一次性的。** 主板第一次收到有效证明后会把 `paired` 写入 NVS，之后不再
静默发送 `K`。换副板请用管理器的「更换副板」流程：旧副板先验证，再插空白新板，
主板用 pending key 完成切换，**Passkey 不会被清空**。

如果新副板里已经有一把别的 key，它会拒绝覆盖；先在上电时按住 BOOT 3 秒清掉它，
再重新走「更换副板」。只有在旧副板也丢失、无法完成验证时，才需要恢复出厂主板
（会清空凭据）。

## LED

| 状态 | 含义 |
|---|---|
| 红灯慢闪 | 还没有 key，等待主板配对 |
| 绿灯常亮 | 已保存 key，链路正常 |

## 清除 key（换主板 / 重新配对）

上电时按住副板 **BOOT** 3 秒以上，红灯亮起后松开，link key **和 KEK** 一起被清除。
清除 KEK 后，主板 NVS 里用旧 KEK 包裹的 DEK 就解不开了；如果还要保留 Passkey，
必须用管理器的「更换副板」流程（旧副板还活着、能完成验证）来转移 DEK，不能先清副板。

## 协议

115200 8N1，换行分隔 ASCII：

| 命令 | 作用 | 回复 |
|---|---|---|
| `K <64 hex>` | 空板保存 key | `OK K` / `ERR HASKEY` |
| `C <32 hex>` | 16 字节 nonce | `P <64 hex>` HMAC / `ERR NOKEY` |
| `E <24 hex>` | 12 字节 nonce | `E <96 hex>`：用 link key 加密的 KEK |
| `S` | 状态 | `S 1` / `S 0` |
| `PING` | 存活 | `PONG` |

HMAC 输入：`nonce(16) || "TECHX-IL"`，密钥是 32 字节 link key。
