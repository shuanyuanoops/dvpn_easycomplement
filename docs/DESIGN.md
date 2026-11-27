# dVPN 设计说明（当前实现）

这份文档解释“现在到底怎么工作、为什么这么设计、哪些还没做”。不是论文，是给实现和答辩用的底稿。

## 1. 拓扑和角色

```
应用
  | 内层 IP 包：源 10.99.0.2，目的 10.99.0.1 或公网 IP
  v
客户端 TUN
  | 外层 UDP/TLS：客户端公网地址 -> entry 的 TLS 网关
  v
tlsgate（入口网关，TLS 1.3 + ECH 终止）
  | 明文固定帧，UDP 转给 entry
  v
entry -> middle -> exit（三层洋葱）
  | exit 解出内层 IP 包
  v
exit TUN -> 本地服务，或（将来）公网出口
```

- **entry**：入口，知道客户端（或 tlsgate）的地址，不知道最终目标。
- **middle**：只知道前后两跳。
- **exit**：知道目标，不知道客户端真实地址；它需要把内层包送到目标。
- **tlsgate**：现在和 entry 部署在一起；它终止 TLS/ECH，entry 只看到网关的 UDP 地址。

## 2. 选路：谁选，客户端知不知道

现在不是客户端自己选。

1. 客户端向 controller 发 `GET /assign`；
2. controller 从注册表里随机选 entry/middle/exit；
3. 客户端拿到这三个 relay 的 ID、地址、身份文档路径；
4. 客户端按这个顺序建洋葱。

所以：

- **controller 随机分配**；
- **客户端知道被分配到哪三跳**，因为它要自己套洋葱；
- 客户端不“挑选” relay，只是接收分配结果。

这和 Tor 的“客户端自己选路径”不同；Tor 客户端确实知道整条路径。源路由必须知道每一跳是谁，否则没法套层。

### 现在的 AS 问题

注册表已加 `AS` 字段；`Assign()` 会优先选 AS 两两不同的 entry/middle/exit。池子无法满足时，退化为任意随机组合，但保证 ID 不重复。

注意：AS 只表示注册时填的归属，不等于可验证的 BGP 归属；controller 也不会自己去查 BGP。

### 分布式选路原型（`internal/assign`）

- 3 个独立 assignment server，每个只选一跳（entry/middle/exit）；
- bulletin board 拼 ticket、重试重复 ID/AS 冲突；
- client view 只有 `entry + token`，没有 middle/exit；
- relay 用 hop token + 自己的 ID 只能查相邻节点；
- `cmd/assignsim` 跑 100 relay / 1000 client。

**但 board 仍持有完整 ticket**：这是“分布式选择”的第一步，不是完整 TorPath
（没有 Neff shuffle、没有门限解密）。client 现在只拿到 entry，还不能自己建完整
洋葱，需要下一步做 telescoping。

## 3. sessionKey 是什么

`sessionKey` 是客户端为**每一跳**生成的 32 字节对称密钥。

- 客户端用 relay 的 X25519 公钥把它封起来（`handshake.Seal`）；
- relay 用自己的 X25519 私钥解开（`handshake.Open`）；
- 之后这一跳的洋葱层用这个 32 B key 做 AES-256-GCM。

它不是 TLS 会话密钥，也不是客户端和服务器的长期密钥；它只用于这一跳的洋葱层，电路结束就丢。

## 4. 握手流程

客户端为每跳生成 `sessionKey`：

- entry/middle 的 sealed 明文：

```text
nextHopID(16) || sessionKey(32)
```

- exit 的 sealed 明文：

```text
sessionKey(32) || replyKey(32) || nonce(8) || clientIP(4)
```

发送顺序：

1. 客户端把三个 sealed key 拼成 handshake payload，发给 entry；
2. entry 解开自己的，拿到 `nextHopID=middle` 和 sessionKey，把剩下的转发给 middle；
3. middle 同样拿到 `nextHopID=exit`，转发给 exit；
4. exit 解开自己的，存 sessionKey、replyKey、nonce、clientIP，回一个加密 ACK；
5. ACK 沿反向 tag 回到客户端；客户端 300 ms 没收到就重试，最多 3 次。

这不是完整 TLS/Noise 握手：会话密钥由客户端生成，relay 只解封自己的那份；ACK 是“整条链装好了”的确认。

## 5. 洋葱数据面

客户端从 TUN 读一个 IP 包，调用 `onion.Build`：

```text
exit 层：next="dest" + payload，用 exit 的 sessionKey 加密
middle 层：next="exit" + 上一层，用 middle 的 sessionKey 加密
entry 层：next="middle" + 上一层，用 entry 的 sessionKey 加密
```

得到固定 1024 B cell，套 entry 的 tag `t0` 和 seq，发给 entry。

- entry 解一层，得到 `next=middle`，把 `t0` 换成 `t1`，发 middle；
- middle 解一层，把 `t1` 换成 `t2`，发 exit；
- exit 解最后一层，得到原始 IP 包，写进 exit TUN。

反向：

- exit 从 TUN 读到回包，按目的 IP 找对应客户端；
- 用 replyKey 加密，套 `t2` 发 middle；
- middle/entry 按 `ReplyPeer` 把 `t2 -> t1 -> t0` 还原；
- 客户端用 replyKey 解密，写回 TUN。

## 6. tag 和 seq

- 每个 relay 自己维护 `in`/`out` map；
- tag 是随机 64 位数，只在本 relay 内检查冲突；
- 没有全局 circuit ID；全局唯一反而会帮助关联；
- 帧头带 seq，relay 按 tag 拒绝重复/旧包；
- tag 有 TTL，闲置会被清理。

## 7. 收据和计量（当前）

### 真传输

每段链路两个半条记录：

```text
sender:   link-half-v1|tag|from|to|sender|packets|bytes
receiver: link-half-v1|tag|from|to|receiver|packets|bytes
```

各自 Ed25519 签名；relay 的 `/links` 暴露自己的半条；`/hash` 暴露某 seq 的包 hash；`cmd/linkaudit` 按 tag 配对、验签、比计数、抽查 hash。

**问题**：两个总数无法区分“丢包”和“多报”。现在 `linkaudit` 是精确比对，有丢包就失败；仿真里有 3σ 容忍，但真传输没有。

### 客户端签用量（已接入）

- 客户端每 200 ms 写一份签名 grant：`session=内层IP`、`node=exit id`、
  `bytes/packets`、epoch；
- exit 在 SIGTERM 时按客户端内层 IP 写签名 claim；
- `cmd/settle` 验双方签名，`paid = min(claim, grant)`，所以节点不能超过
  客户端签的量多收；
- `scripts/run_usage.sh` 实测 `grant=398 claim=398 paid=398`；
- `cmd/settle` demo 用 grant=1000、claim=1500 证明封顶到 1000。

局限：客户端 200 ms 才写一次，进程被 SIGKILL 时最后一次可能没写；exit 只在
SIGTERM 时写 claim；多客户端的 usage 还没单独跑。

### 将来

- 逐包/逐批 ACK，让“丢包 vs 多报”可裁决；
- 邻居双签只做审计，不作为唯一付款依据。

## 8. 链

`internal/chain` 是模拟账本：注册、质押、结算、争议、Merkle proof、nonce、原子出块。

**但它没有接进真传输**：

- `cmd/controller` 读本地 `relays.json`，不读链；
- `run_e2e`/`run_cluster` 不提交收据；
- 收据没上链。

所以“注册上链/结算上链”目前只是 `cmd/chain` 的 demo。

## 9. TLS/ECH

- 客户端 ↔ tlsgate：TLS 1.3；
- tlsgate ↔ entry：UDP；
- ECH：`internal/ech` 生成 X25519/HKDF-SHA256/AES-128-GCM 的 ECHConfig；客户端加载 config list；
- 证书是自签，客户端 `-tls-insecure`，**只加密不认证**；要认证需要私有 CA/pin/公共 CA。

TLS 只保护 client→gateway，不保护 middle/exit 之间的 UDP 洋葱。

## 10. 为什么不用门限

门限（t-of-n）是“一个秘密分成 n 份，t 份才能拼回来”。洋葱不需要拼回全局秘密：

- 每跳只解自己那层；
- 用门限反而让任意 t 个 relay 能合谋解一层；
- 所以用分层加密 + 源路由。

## 11. 当前边界

- 多客户端：exit 已按内层 IP 分流，但双客户端 e2e 还没跑；
- 公网出口：没有 NAT/代理，只有 exit TUN 本地 HTTP；
- 计费：邻居双签 + 精确比对，没有客户端签用量；
- 链：模拟，未接真传输；
- 流量分析：没有 cover/padding；
- 身份：TOFU + 自签证书。
