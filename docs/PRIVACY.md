# 隐私声明与边界（当前版本）

这份文档明确说明：**当前实现不是匿名网络，也不是可部署的隐私 dVPN。**

## 真实传输能提供什么

- 3-hop UDP 转发：client → entry → middle → exit → sink。
- 每跳 AES-GCM 洋葱信元；固定 1024 B 帧；per-hop tag；seq 防重放。
- entry 看到 client 的 IP，exit 看到目标 IP；没有单点同时看到两者。
- 握手用 X25519；relay 的 X25519 公钥由 Ed25519 身份签名（TOFU）。
- 反向 reply/ACK 用握手带回的 reply key 加密。

## 真实传输不能提供什么

- **没有 TLS，也没有 ECH**：当前 payload 是裸 UDP 转发，不存在 SNI。
- **不隐藏目标 IP**：exit 必须知道目标才能转发。
- **不抗 E+X 合谋**：entry 和 exit 交换时间/字节即可关联。
- **不抗全局观察者/流量分析**：没有 cover traffic、batching、padding 策略。
- **身份是 TOFU**：client 从文件读 Ed25519 公钥，没有 registry/CA 固定。

## 仿真里的隐私指标

- `-cover N` 是**合成观测**，不是真实 cover 流量。
- `anonymity_set` / `linkability` 只用于比较趋势，不是部署保证。
- 所有会话字节数/启动时间相同，anon 值本身偏乐观。

## 报告里应该怎么写

不要说“匿名 dVPN”。应该说：

> 我们在 3-hop 覆盖层上研究“隐私约束下的计量”：谁在正常情况下知道什么、合谋/故障下计量误差多大、链上结算需要哪些承诺。

## 要变成真实隐私还需要

1. TLS 1.3 + ECH（RFC 9849）集成；DNS 走出口/DoH。
2. 真实 cover traffic / batching / padding。
3. 抗流量分析的评估（真实 trace，而不是合成观测）。
4. registry 固定 relay 身份，替代 TOFU。
5. 多路径/混合网络（如需要更强匿名性）。
