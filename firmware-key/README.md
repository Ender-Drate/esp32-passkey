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

上电时按住副板 **BOOT** 3 秒以上，红灯亮起后松开，key 被清除。
清除后如果主板仍然配对正常，它不会自动重新配对——请用管理器的「更换副板」
流程（旧副板验证 → 新板配对），这样不会丢失 Passkey。

## 协议

115200 8N1，换行分隔 ASCII：

| 命令 | 作用 | 回复 |
|---|---|---|
| `K <64 hex>` | 空板保存 key | `OK K` / `ERR HASKEY` |
| `C <32 hex>` | 16 字节 nonce | `P <64 hex>` HMAC / `ERR NOKEY` |
| `S` | 状态 | `S 1` / `S 0` |
| `PING` | 存活 | `PONG` |

HMAC 输入：`nonce(16) || "TECHX-IL"`，密钥是 32 字节 link key。
