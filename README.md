# dvpn-sim

3-hop dVPN 仿真骨架。Go 标准库，无第三方依赖。

## 运行

### 真传输（本机 UDP 三跳）

```bash
bash scripts/run_local.sh       # 固定 3 跳 demo
bash scripts/run_cluster.sh     # 2x2x2 relay + controller 随机分配
bash scripts/run_tun_lab.sh     # TUN 端到端：client TUN -> 洋葱 -> exit TUN -> HTTP
bash scripts/run_tls.sh         # TLS 1.3 入口网关
bash scripts/run_tls_ech.sh     # TLS 1.3 + ECH 入口网关
bash scripts/run_e2e.sh         # TUN + TLS/ECH + 链路双签，一条龙
bash scripts/run_multi.sh       # 两个客户端、两个内层 IP，exit 按目的 IP 分流
bash scripts/run_nat.sh         # exit 转发 + MASQUERADE 到假公网
bash scripts/run_usage.sh       # TUN + TLS/ECH + 双签 + 客户端签用量结算
go run ./cmd/assignsim          # 100 relay / 1000 client 的分布式选路模拟
go run ./cmd/tunnelsim          # client 只知道 entry，逐跳扩展 3 个密钥
go run ./cmd/settle             # 客户端签 grant -> 节点 claim 封顶 demo
# 集群脚本还会跑 cmd/linkaudit：逐链路双签 + 随机 challenge
# TUN 模式（需要 root/TUN 权限）：
#   client -tun -tun-name dvpn0 ... ; exit relay -tun -tun-name dvpn1 ...
```

会启动 `sink ← exit ← middle ← entry ← client`，发送 4000 个 1024 B 帧，
打印吞吐、单向延迟和每个 relay 的包数/字节数；最后用 `cmd/audit` 验证
签名收据并检查 `client -> entry -> middle -> exit -> sink` 的字节链。

### 仿真

```bash
go run ./cmd/sim -scenario all
go run ./cmd/sim -scenario overreport -clients 120 -packets 50
go run ./cmd/sim -scenario honest -dns local
go run ./cmd/sim -scenario honest -hops 2 -cell 512
go run ./cmd/sim -scenario honest -cover 100
go run ./cmd/sim -scenario honest -hops-min 3 -hops-max 5
go run ./cmd/sim -scenario overreport -loss 0.1 -dup 0.1
go run ./cmd/bench
go run ./cmd/chain
go test ./...
```

## 当前模型

- 3-hop 电路：client → entry → middle → exit → destination。
- **真洋葱信元**：AES-256-GCM 逐层加密，固定 1024 B 帧；3 跳有效载荷 878 B。
- **反向路径**：per-hop tag 重写（`t0 -> t1 -> t2`）+ 上一跳表；客户端可测 RTT。
- **X25519 握手 + 身份绑定**：Ed25519 身份签 X25519 公钥；exit 回 ACK，失败重试。
- **反向加密**：exit 用握手带回的 reply key 加密回复。
- **seq 防重放**：relay 按 tag 拒绝重复/旧包。
- **交叉签 + 挑战**（仿真）：相邻 hop 双签链路收据；每包 hash + 随机抽查。
  - 每跳只解一层，只知道下一跳；出口才知道 `dest`。
  - 交换节点看不到最终目标；只有出口看到。
- 每个包按链路延迟 + 串行化时间推进；链路有排队（`nextFree`）。
- 每个 hop 记录**有效载荷字节**，生成 Ed25519 收据 + hash chain。
- 审计按概率抽样，用 client + E/M/X 四个读数的中位数找 outlier：
  - 节点多报 → 罚没节点质押；
  - 客户端少报 → 标记客户端，不罚节点。
- DNS：
  - `-dns tunnel`（默认）：DNS 包走电路，出口解析；`dns_packets` 计数。
  - `-dns local`：模拟本地解析，`local_dns_leaks` 计数（泄漏）。
- 知识矩阵：C/E/M/X/D 各自能看到什么。

## 已知限制（下一轮补）

- 电路密钥由模拟器预共享，还没有 X25519 电路建立。
- 收据是单方签 + 链，不是相邻节点交叉签。
- 审计是“读数比对”，不是随机数据挑战。
- 没有 E+X 关联实验、padding、质押账本/结算。
- 签名/验签做了，但收据没有在审计里验签。

## 目录

```
cmd/sim/           CLI 仿真
cmd/relay/         真 UDP relay（entry/middle/exit）
cmd/client/        真 UDP 客户端
cmd/sink/          接收端，统计吞吐/延迟
cmd/audit/         验签 + 字节链审计
internal/frame/    1024 B 固定帧
internal/onion/    AES-GCM 洋葱信元（build/peel）
internal/model/    Node, Circuit, Packet, Receipt
internal/sim/      事件循环、链路、计量、审计
scripts/           run_local.sh
docs/              ENGINEERING.md（设计文档）
STATUS.md          当前状态/指标/限制
docs/DESIGN.md     设计说明：选路/握手/sessionKey/洋葱/收据/链
docs/PRIVACY.md    隐私声明与边界（明确降级）
internal/chain/     模拟链（注册/质押/结算/罚没）
internal/merkle/    收据 Merkle root / proof
```
