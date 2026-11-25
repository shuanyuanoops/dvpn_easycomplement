# dvpn-sim 工程设计文档

> 版本：v0.3.x
> 范围：3-hop dVPN 的仿真 + 本机 UDP 真传输 + 计量骨架。
> 读者：实现者 / 评审 / 队友。

---

## 1. 目标与非目标

### 1.1 目标

1. 一个可运行的 3-hop 数据面：客户端 → entry → middle → exit → destination。
2. 固定大小信元 + 逐层加密，避免“每跳变小”泄漏路径位置。
3. 可度量的计量骨架：每跳计数、签名收据、审计、罚没。
4. 能跑两类实验：
   - 仿真：大规模、多场景（honest / overreport / underreport / hop 数 / DNS）。
   - 真传输：本机 UDP，验证封装、转发、延迟、吞吐。

### 1.2 非目标（当前版本）

- 不做完整 Tor / Sphinx / Neff / DKG。
- 不做真实区块链结算。
- 不做 TCP fallback、多路径、NAT 穿透、真实公网部署。
- 不做 ECH 的真实 TLS 集成（只在仿真里建模 DNS 泄漏）。
- 不声称“证明转发”；只做“可检测、可定价的作弊上界”。

---

## 2. 当前状态

| 模块 | 状态 |
|---|---|
| 3-hop 仿真 | 可用（`cmd/sim`） |
| AES-GCM 洋葱信元 | 可用（`internal/onion`） |
| 固定 1024 B 帧 | 可用（`internal/frame`） |
| 本机 UDP 真传输 | 可用（`cmd/relay`、`cmd/client`、`cmd/sink`） |
| 反向路径 / RTT | 可用（per-hop tag 重写） |
| X25519 握手 / 会话密钥 | 可用（逐跳 seal + 安装） |
| DNS 泄漏对比 | 仿真里可用（`-dns local/tunnel`） |
| 每跳计数 + 收据 | 仿真里有；真传输有进程级收据 |
| 交叉签 link receipt | 仿真里有（E-M、M-X 双方签） |
| 随机挑战 | 仿真里有（每会话抽 3 个 seq） |
| 审计/罚没 | 仿真里有；真传输有字节链审计 |
| ECH / padding / E+X 关联 | 未做 |

---

## 3. 架构

```
仿真（cmd/sim）
  ├─ 事件循环、链路延迟/带宽/队列
  ├─ 3-hop 电路、onion、DNS 模式
  └─ 计量/审计/罚没

真传输（cmd/relay + client + sink）
  client --UDP 1024B frame--> entry
  entry  --UDP 1024B frame--> middle
  middle --UDP 1024B frame--> exit
  exit   --UDP payload------> sink
```

两者共用 `internal/onion`、`internal/frame`、`internal/model`。

---

## 4. 数据面

### 4.1 为什么 UDP

- 隧道协议跑在 UDP 上，避免 TCP-over-TCP 的头阻塞。
- 丢包时由上层（QUIC/WireGuard/应用）处理，而不是隧道层重传。
- UDP 的代价：部分网络封锁 UDP，需要 TCP fallback；当前不做。

### 4.2 帧格式

线上固定 1024 B：

```
+--------+--------+-----------+-------------------+------------------+
| 2B len | 1B type| 8B circuit| inner onion cell  | zero padding     |
+--------+--------+-----------+-------------------+------------------+
```

- 每个 relay peel 一层后，把内层重新装进 1024 B 帧再转发。
- 这样线上大小恒定，不会 1024 → 980 → 936 泄漏跳数。
- 有效载荷：3 跳时 890 B（1022 B cell − 132 B onion 开销）。

### 4.3 洋葱信元

- 每层：16 B next-hop + 12 B nonce + ciphertext + 16 B tag。
- 每跳只解一层，只知道下一跳；出口才知道 `dest`。
- 会话密钥通过 X25519 握手建立：client 为每跳生成 32 B 会话密钥，
  用 relay 的静态 X25519 公钥 seal，沿链逐跳安装；不再用命令行预共享密钥。
- relay 在 `-pubkey-out` 写静态公钥；client 用 `-pub-*` 读取。
- handshake 帧的 tag 也按 per-hop 重写；数据帧用同一 tag 查会话密钥。

### 4.4 反向路径

已实现（本机 demo）：

- forward 帧携带 8 B tag；每个 relay 把入 tag 映射到出 tag，转发时重写：
  `entry: t0 -> t1`、`middle: t1 -> t2`、`exit: t2 -> prev`。
- reply 帧用出 tag 查回入 tag，逐跳重写；每个 relay 只看到相邻 tag。
- 状态：每条活跃电路两条表项（`in[tag] -> {prev, outTag}`、`out[outTag] -> inTag`），
  复杂度 O(active circuits)。
- 客户端按自己的 t0 过滤 reply，计算 RTT。

限制：

- 还没有 tag 过期/清理；长期运行需要 idle timeout。
- reply 未做逐层加密；本机 demo 可接受，公网需要补。
- 每个 circuit 只支持单客户端；多客户端需要独立 tag。

---

## 5. 隐私

### 5.1 3-hop 知识分割

| 参与方 | C IP | D IP | SNI | 字节数 |
|---|---|---|---|---|
| C | ✓ | ✓ | ✓ | ✓ |
| E | ✓ | ✗ | ✗ | ✓ |
| M | ✗ | ✗ | ✗ | ✓ |
| X | ✗ | ✓ | ✗ | ✓ |
| D | ✗ | — | — | ✓ |

- 最小 2 跳才有“没有单点同时知道 C 和 D”；3 跳多一层隔离。
- 不防 E+X 合谋，也不防全局观察者的时序关联。

### 5.2 ECH / DNS

- ECH 只隐藏 TLS ClientHello 里的 SNI；不隐藏 D 的 IP、DNS、时序。
- DNS 必须走隧道（或 DoH via exit），否则本地解析泄漏域名。
- 仿真里用 `-dns local/tunnel` 对比泄漏计数；真实 ECH 集成未做。

### 5.3 Padding / 流量伪装

- 固定 1024 B 帧 = 大小伪装的基础。
- 时间伪装（batching/delay）、体积伪装（cover traffic）未做。
- 谁做：客户端入口 padding；relay re-frame；exit strip。

---

## 6. 计量

### 6.1 当前策略

- 每跳记录包数/字节数。
- 收据：`session/hop/seq/bytes/prevHash/hash/sig`，Ed25519 单方签。
- hash chain 防篡改历史。
- 审计：client + E/M/X 四个读数取中位数，找 outlier。
- 罚没：节点质押的 10%。

### 6.2 已知弱点

1. 签名只证明“我签了这个数”，不证明“数是真的”。
2. 中位数在 4 个读数里可被 2 个合谋者带偏。
3. 没有相邻交叉签、没有随机挑战、没有验签。
4. 没有真实质押账本，只有计数。
5. 真传输还没接计量。

### 6.3 已实现（v0.7）

1. **交叉签 link receipt**：E-M、M-X 两段，sender/receiver 双方 Ed25519 签
   `session|from|to|seqStart|seqEnd|bytes`；audit 验双签 + 比对接收方字节。
2. **每包 hash + 随机挑战**：每跳存 `H(session|seq|bytes)`；audit 每会话抽 3 个 seq，
   缺 hash 或字节不符就失败。它能抓“没转发”，但抓不到“转了却多报字节”。

### 6.4 计划

1. 客户端签用量：节点不能收超过客户端签的额度。
2. 质押/罚没账本：经济约束。
3. 真传输上的交叉签/挑战（当前只在仿真里）。

---

## 7. 模块

| 包 | 职责 |
|---|---|
| `internal/model` | Node/Circuit/Packet/Receipt |
| `internal/onion` | AES-GCM 逐层 build/peel |
| `internal/frame` | 1024 B 固定帧 encode/decode |
| `internal/sim` | 事件循环、链路、计量、审计 |
| `internal/receipt` | 真传输的签名收据（计划） |
| `cmd/relay` | 真 UDP relay |
| `cmd/client` | 真 UDP client |
| `cmd/sink` | 接收端 |
| `cmd/sim` | 仿真 CLI |

---

## 8. 失败模式

| 失败 | 现象 | 处理 |
|---|---|---|
| 帧长度错 | relay 丢包并日志 | 当前丢弃 |
| GCM 校验失败 | relay 丢包 | 当前丢弃 |
| next hop 不匹配 | relay 丢弃 | 当前丢弃 |
| UDP 丢包 | sink 收不到 | 上层重传/QUIC |
| relay 挂 | 路径断 | 重新选路（未做） |
| 收据不符 | 审计标记 | 罚没/争议 |

---

## 9. 更硬但当前不实现的方案

按“硬度 / 代价”列，留作后续或对比章节：

1. **TEE 计数器**：enclave 内计数、签聚合；外部无日志；信任硬件厂商；侧信道风险。
2. **逐包票据（Orchid/HOPR）**：支付与转发原子绑定，节点不能多收；每包密码学开销大。
3. **ZK 计量证明**：证明“计数与收据一致”而不泄露内容；电路复杂、证明慢。
4. **DKG + Neff shuffle**：无可信 dealer 的阈值解密 + 可验证洗牌；开发量大。
5. **完整 ECH 集成**：真实 TLS ClientHello 加密；需要 HPKE/证书/DNS 配置。
6. **Mixnet 延迟/cover traffic**：强抗时序；交互式 VPN 延迟不可接受。
7. **TCP fallback**：UDP 被封时可用；TCP-over-TCP 头阻塞，性能差。
8. **多路径**：同时走多条链路，聚合/切换；调度和计费复杂。
9. **真实链上结算**：质押/支付/罚没上链；性能与隐私代价。
10. **信誉市场**：多维度信誉、置信区间；可被博弈。
11. **匿名凭证（Privacy Pass）**：支付与身份不可关联；盲签名/双花处理。
12. **后量子 KEM**：抗量子；当前未选型。

> 这些不是“做不到”，是“当前 8 周内不做”；报告里要写清 trade-off。

---

## 10. 开放问题

1. 3-hop 的延迟成本是否值得？2-hop 够不够？
2. 客户端签用量 + 交叉签，能否把作弊上界压到可接受？
3. 真实 ECH 集成需要多少工程量？
4. 反向路径用哪种方案？
5. 节点选择：纯随机 vs 约束+随机？
