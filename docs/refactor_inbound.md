对，我建议把 **2、3、4 一次性重构掉**。它们其实应该收敛成同一个模型：

> **UDP ingress 只负责“收包 + 快速投递”；每个 UDP flow 自己拥有一个异步 worker，真正的 DNS / route / open_datagram / send / recv 都在 worker 里做。**

现在 Rust 最大的问题，就是 `InboundUdpSession::run()` 的 `select!` 看着挺并发，实际上 branch 进去以后：

```rust
flows.handle_packet(...).await?
```

会把整个 session 卡住。在当前代码里，`handle_packet()` 又可能执行 DNS、创建 datagram、`send_to().await`，所以一个慢 flow 足以拖住整个 session。

我会这样改。

---

# 一、目标结构

最终变成：

```text
                     UDP packet
                         │
                         ▼
                InboundUdpManager
                  快速分类 / dispatch
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
          flow A      flow B      flow C
          worker      worker      worker
              │          │          │
          route/dial   ...        ...
          send/recv
              │
              ▼
          ReplySink
              │
        ┌─────┴─────┐
        ▼           ▼
     SOCKS/UDP     TUN
     codec         output_tx
```

最重要的是：

```text
flow A 卡住
```

只能变成：

```text
flow A 卡住
flow B 正常
flow C 正常
UDP ingress 正常
TUN 正常
```

而不能变成：

```text
flow A 卡住
    ↓
整个 UDP session 卡住
    ↓
整个网络开始抽风
```

---

# 二、先把 `InboundUdpFlows` 从 Session 里拿出去

现在：

```rust
pub(crate) struct InboundUdpSession<C> {
    codec: C,
    flows: InboundUdpFlows,
}
```

这意味着每个 session 自己管理：

```rust
HashMap<UdpFlowId, UdpFlowState>
```

我建议改成：

```rust
pub struct InboundHandler {
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    dns: InboundDnsPolicy,

    udp: Arc<InboundUdpManager>,
}
```

所有协议最终共享：

```rust
Arc<InboundUdpManager>
```

变成：

```text
SOCKS UDP ─┐
Yuubinsya ─┼──> InboundUdpManager
TProxy UDP ┤
TUN UDP ───┘
```

这才更接近 Go 的：

```text
所有 packet
    ↓
nat.Table
    ↓
SourceControl
```

Go 当前确实是公共 `nat.Table`，然后按照 `MigrateID` 或 source address 找 `SourceControl`。

---

# 三、不要让 Manager 自己 await 网络 I/O

这里很重要。

千万别写成：

```rust
async fn handle_packet(&mut self, packet: Packet) {
    let flow = self.find_flow(...);

    flow.open_datagram().await;
    flow.send_to(...).await;
}
```

那只是把阻塞从：

```text
InboundUdpSession
```

搬到：

```text
InboundUdpManager
```

人类经典重构：问题换个文件名继续存在。

Manager 必须只做：

```text
查 flow
没有就创建 worker
try_send(packet)
return
```

类似：

```rust
pub struct InboundUdpManager {
    tx: mpsc::Sender<UdpIngress>,
}
```

然后：

```rust
struct UdpManagerTask {
    flows: HashMap<UdpSourceKey, UdpFlowHandle>,
}
```

manager loop：

```rust
while let Some(packet) = rx.recv().await {
    let key = packet.key();

    let flow = flows.entry(key).or_insert_with(|| {
        spawn_udp_flow_worker(...)
    });

    match flow.tx.try_send(packet) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            // drop
        }
        Err(mpsc::error::TrySendError::Closed(packet)) => {
            // recreate worker / drop
        }
    }
}
```

这里**绝对不要 `.send().await`**。

---

# 四、真正的核心：每个 UDP flow 一个 worker

Go 的 `SourceControl` 本质上已经是这个模型。

它内部有：

```go
sentPackets
receivedPackets
notifySentPacket
notifyReceivedPacket
conn
```

并且自己有 goroutine：

```go
go s.run()
```

Rust 可以直接把这个思想翻译成 async actor。

例如：

```rust
struct UdpFlowHandle {
    tx: mpsc::Sender<UdpFlowCommand>,
}
```

然后：

```rust
enum UdpFlowCommand {
    Packet(UdpPacket),
    Close,
}
```

创建：

```rust
fn spawn_udp_flow_worker(
    key: UdpSourceKey,
    inbound: Arc<InboundHandlerCore>,
) -> UdpFlowHandle {
    let (tx, rx) = mpsc::channel(FLOW_QUEUE_SIZE);

    tokio::spawn(async move {
        UdpFlowWorker::new(key, inbound, rx)
            .run()
            .await;
    });

    UdpFlowHandle { tx }
}
```

---

# 五、worker 自己负责 route + open_datagram

第一次收到 packet：

```rust
async fn ensure_datagram(
    &mut self,
    packet: &UdpPacket,
) -> Result<()> {
    if self.datagram.is_some() {
        return Ok(());
    }

    let mut context = self.inbound.context_with_source(
        packet.peer.clone(),
        packet.target.clone(),
    );

    self.inbound.selector.route_context(&mut context);

    let datagram = self
        .inbound
        .selector
        .select(&context)
        .open_datagram(&context)
        .await?;

    self.datagram = Some(Arc::from(datagram));

    Ok(())
}
```

这里 `.await` 多久都无所谓。

因为它现在只堵：

```text
这个 flow worker
```

而不是：

```text
InboundUdpSession
```

---

# 六、worker 的 run loop 应该同时处理 send / recv / idle / close

理想结构：

```rust
async fn run(mut self) {
    loop {
        tokio::select! {
            command = self.rx.recv() => {
                match command {
                    Some(UdpFlowCommand::Packet(packet)) => {
                        if let Err(err) = self.send_packet(packet).await {
                            break;
                        }
                    }

                    Some(UdpFlowCommand::Close) | None => {
                        break;
                    }
                }
            }

            result = self.recv_remote(),
                if self.datagram.is_some() =>
            {
                match result {
                    Ok(reply) => {
                        self.handle_reply(reply).await;
                    }

                    Err(_) => {
                        break;
                    }
                }
            }

            _ = &mut self.idle_timer => {
                break;
            }
        }
    }

    self.cleanup().await;
}
```

也就是：

```text
一个 flow actor
     │
 ┌───┼────────────┐
 ▼   ▼            ▼
send recv        idle
```

这样 flow 自己就是完整生命周期 owner。

---

# 七、`InboundUdpSession` 要变得非常傻

这是关键。

现在：

```rust
received = codec.recv() => {
    flows.handle_packet(...).await?;
}
```

应该变成：

```rust
received = codec.recv() => {
    let Some(request) = received? else {
        break;
    };

    udp_manager.dispatch(
        UdpIngress {
            ...
        }
    )?;
}
```

`dispatch()` 最好甚至不是 async：

```rust
pub fn dispatch(&self, packet: UdpIngress) -> DispatchResult {
    match self.tx.try_send(packet) {
        Ok(()) => DispatchResult::Accepted,

        Err(TrySendError::Full(_)) => {
            DispatchResult::Dropped
        }

        Err(TrySendError::Closed(_)) => {
            DispatchResult::Closed
        }
    }
}
```

于是 session loop 就变成真正的 event loop：

```rust
loop {
    tokio::select! {
        request = codec.recv() => {
            ...
            manager.dispatch(packet);
        }

        Some(reply) = reply_rx.recv() => {
            codec.send(reply).await?;
        }

        close = close_rx.recv() => {
            ...
        }
    }
}
```

注意：

```rust
codec.send(reply).await
```

还是可能慢。

但这时候堵的是：

```text
这个 client/session
```

不是所有 UDP flow。

这是合理的。

---

# 八、Reply 必须抽象出来

因为 global manager 不应该知道：

```text
这是 SOCKS5
还是 Yuubinsya
还是 TUN
```

可以定义：

```rust
#[derive(Clone)]
pub enum UdpReplySink {
    Session(mpsc::Sender<InboundUdpResponse>),

    #[cfg(feature = "tun")]
    Tun(mpsc::Sender<ProxyOutput>),
}
```

但这会让 core 层知道 TUN 类型，我不是很喜欢。

更干净的是 trait：

```rust
pub trait UdpReplySink: Send + Sync {
    fn send<'a>(
        &'a self,
        reply: UdpReply,
    ) -> BoxFuture<'a, Result<()>>;
}
```

比如 SOCKS：

```rust
struct SessionReplySink {
    tx: mpsc::Sender<InboundUdpResponse>,
}
```

TUN：

```rust
struct TunReplySink {
    tx: mpsc::Sender<ProxyOutput>,
}
```

然后 packet：

```rust
struct UdpIngress {
    key: UdpSourceKey,

    peer: Endpoint,
    target: Endpoint,
    payload: Vec<u8>,

    reply: Arc<dyn UdpReplySink>,
}
```

worker 根本不关心协议：

```rust
self.reply
    .send(UdpReply {
        target,
        payload,
    })
    .await?;
```

这样结构会很漂亮。

---

# 九、`UdpSourceKey` 怎么定义非常重要

Go：

```go
key := pkt.MigrateID

if key == 0 {
    key = srcAddr.Comparable()
}
```

Rust 最好也不要继续完全依赖 protocol-specific：

```rust
UdpFlowId
```

而应该有一个公共 key：

```rust
enum UdpSourceKey {
    Migrate(u64),

    Source {
        inbound_id: String,
        source: SocketAddr,
    },
}
```

例如：

```rust
impl UdpIngress {
    fn source_key(&self) -> UdpSourceKey {
        if let Some(id) = self.migrate_id {
            return UdpSourceKey::Migrate(id);
        }

        UdpSourceKey::Source {
            inbound_id: self.inbound_id.clone(),
            source: self.source,
        }
    }
}
```

### 为什么我建议多一个 `inbound_id`

Go 没有。

严格照 Go：

```text
key = source
```

但 Rust 做成 global manager 后，如果：

```text
inbound A 127.0.0.1:1080
inbound B 127.0.0.1:2080
```

恰好两个客户端 source 都是：

```text
192.168.1.5:50000
```

不应该莫名共享一个 flow。

所以我会稍微比 Go 更严格：

```text
(inbound_id, source)
```

full-cone 行为照样保留。

---

# 十、这样就自然解决 full-cone

不要 key：

```text
source + destination
```

而是：

```text
source
```

同一个 worker：

```text
client 192.168.1.5:12345
          │
          ├── 8.8.8.8:53
          ├── 1.1.1.1:53
          └── 9.9.9.9:53
```

都是：

```text
UdpFlowWorker(source=192.168.1.5:12345)
```

内部一个 outbound datagram。

这正是 Go `SourceControl` 的主要价值。

---

# 十一、route cache 也应该放到 worker

Go `SourceControl` 里面有：

```go
resolvedIPCache
reverseNATMap
dispatchCache
contextCache
```

Rust 可以对应：

```rust
struct UdpFlowWorker {
    ...

    datagram: Option<Arc<dyn AsyncDatagram>>,

    route_cache: HashMap<Endpoint, Endpoint>,
    resolved_cache: HashMap<Endpoint, SocketAddr>,
    reverse_nat: HashMap<SocketAddr, Endpoint>,

    context: Option<FlowContext>,
}
```

注意：

**这些东西应该 flow-local，而不是 global Mutex。**

这样：

```text
worker A
  └ cache A

worker B
  └ cache B
```

不需要锁。

这也是 actor 模型的另一个巨大好处。

---

# 十二、重点来了：队列到底怎么处理

这个就是你说的第 4 点，我觉得必须明确规范。

我建议分三类。

### A. 原始 UDP packet

必须：

```rust
try_send()
```

**队列满就 drop。**

不要：

```rust
send().await
```

因为 UDP 数据包本身就允许丢，而且不能为了一个堵塞 consumer 反过来停止读取 TUN。

例如：

```rust
match flow.tx.try_send(UdpFlowCommand::Packet(packet)) {
    Ok(()) => {}

    Err(TrySendError::Full(_)) => {
        monitor.udp_dropped(...);
    }

    Err(TrySendError::Closed(packet)) => {
        // 可选择重建 worker
    }
}
```

这跟 Go 当前 ringbuffer 满时直接 drop 的策略是一致的。

---

### B. UDP reply

这里有两个选择。

我更偏向：

```rust
try_send()
```

因为 reply 依然是 UDP。

如果客户端已经消费不过来了：

```text
remote packets
    ↓
reply queue 满
    ↓
drop
```

比：

```text
remote recv task 卡住
```

更符合 UDP。

例如：

```rust
match reply_tx.try_send(reply) {
    Ok(()) => {}

    Err(TrySendError::Full(_)) => {
        monitor.udp_reply_dropped(...);
    }

    Err(TrySendError::Closed(_)) => {
        break;
    }
}
```

---

### C. control message

例如：

```text
Close
Shutdown
Reload
```

不能 drop。

应该独立用：

```rust
watch
broadcast
oneshot
CancellationToken
```

不要和 packet queue 混用。

比如：

```rust
struct UdpFlowWorker {
    data_rx: mpsc::Receiver<UdpPacket>,
    cancel: CancellationToken,
}
```

那么：

```rust
tokio::select! {
    packet = data_rx.recv() => ...
    _ = cancel.cancelled() => break,
}
```

---

# 十三、所以不要一个 queue 包打天下

我会明确规定：

| 类型 | 策略 |
| --- | --- |
| ingress UDP packet | bounded + `try_send` + drop |
| per-flow packet | bounded + `try_send` + drop |
| remote UDP reply | bounded + `try_send` + drop |
| close/shutdown | reliable |
| config/reload | reliable |
| accounting | 最好非阻塞 |

这样网络拥堵时：

```text
数据掉一些
```

而不是：

```text
整个 runtime 停住
```

UDP 就应该这么活。

---

# 十四、DNS 也应该顺便移出去

虽然你这次重点是 2/3/4，但如果按这个模型改，DNS 最好一起处理。

现在不要：

```rust
manager.dispatch(packet)
    -> manager await dns
```

而可以：

```text
Ingress
   │
   ├ DNS candidate
   │     ↓
   │   DNS task
   │     ↓
   │   ReplySink
   │
   └ normal
         ↓
      FlowWorker
```

也就是说：

```rust
fn dispatch(&self, packet: UdpIngress) {
    if self.dns.should_hijack(...) {
        self.spawn_dns(packet);
        return;
    }

    self.dispatch_flow(packet);
}
```

不过不能无上限：

```rust
tokio::spawn()
tokio::spawn()
tokio::spawn()
```

最后 DNS flood 给你变成 task flood。

应该有：

```rust
Semaphore
```

比如：

```rust
dns_limit: Arc<Semaphore>
```

或者 DNS 自己也有 bounded queue + worker pool。

例如：

```text
DNS queue 256
   │
   ├ worker 1
   ├ worker 2
   ├ ...
   └ worker N
```

---

# 十五、flow worker 的完整伪代码

大概会长这样：

```rust
struct UdpFlowWorker {
    key: UdpSourceKey,

    inbound: Arc<InboundCore>,
    rx: mpsc::Receiver<UdpIngress>,

    datagram: Option<Arc<dyn AsyncDatagram>>,

    last_seen: Instant,
}
```

```rust
impl UdpFlowWorker {
    async fn run(mut self) {
        let mut recv_buf = vec![0; self.inbound.udp_buffer_size()];

        loop {
            if let Some(datagram) = self.datagram.clone() {
                tokio::select! {
                    packet = self.rx.recv() => {
                        let Some(packet) = packet else {
                            break;
                        };

                        self.last_seen = Instant::now();

                        if self.send(packet).await.is_err() {
                            break;
                        }
                    }

                    result = datagram.recv_from(&mut recv_buf) => {
                        let Ok((n, from)) = result else {
                            break;
                        };

                        self.last_seen = Instant::now();

                        let reply = UdpReply {
                            from,
                            payload: recv_buf[..n].to_vec(),
                        };

                        self.reply(reply);
                    }

                    _ = tokio::time::sleep_until(
                        self.last_seen + UDP_IDLE_TIMEOUT
                    ) => {
                        break;
                    }

                    _ = self.cancel.cancelled() => {
                        break;
                    }
                }
            } else {
                let Some(packet) = self.rx.recv().await else {
                    break;
                };

                if self.init(&packet).await.is_err() {
                    break;
                }

                if self.send(packet).await.is_err() {
                    break;
                }
            }
        }

        self.cleanup().await;
    }
}
```

实际 idle timer 最好别每次重新创建，维护一个 `Sleep` reset 即可。

---

# 十六、还有一个很重要的 race：worker 退出后 manager 的 handle 还在

比如：

```text
manager:
key -> tx A

worker A idle timeout
      ↓
退出

manager 还保留 tx A
```

下一包：

```rust
tx.try_send()
```

会返回：

```rust
Closed(packet)
```

可以这么处理：

```rust
match handle.tx.try_send(Packet(packet)) {
    Err(TrySendError::Closed(Packet(packet))) => {
        flows.remove(&key);

        let flow = spawn_worker(...);

        let _ = flow.tx.try_send(Packet(packet));

        flows.insert(key, flow);
    }

    ...
}
```

或者 worker 退出时回 manager：

```rust
ManagerEvent::FlowClosed {
    key,
    generation,
}
```

最好带 generation：

```rust
struct UdpFlowHandle {
    generation: u64,
    tx: ...
}
```

这样旧 worker 退出不会误删新 worker。

经典 ABA，小东西，却很喜欢在你准备睡觉的时候出现。

---

# 十七、manager 本身也最好是 actor，而不是 `Mutex<HashMap>`

别做：

```rust
Arc<Mutex<HashMap<UdpSourceKey, UdpFlowState>>>
```

然后所有 session：

```rust
lock().await
```

否则你辛辛苦苦去掉了 session 阻塞，又造了一个全局 async mutex。

建议：

```text
Ingress
  ↓
manager mpsc
  ↓
single manager task
  ↓
HashMap
```

HashMap 只被一个 task 操作：

```rust
HashMap<UdpSourceKey, UdpFlowHandle>
```

**完全不用锁。**

这跟 Go 的：

```text
SourceControl per source
```

思路也很接近，只是 Rust 用 actor/message passing 会更自然。

---

# 十八、最终组件我会拆成这样

```rust
pub struct InboundUdpManager {
    ingress_tx: mpsc::Sender<UdpIngress>,
}
```

内部：

```rust
struct InboundUdpManagerTask {
    inbound: Arc<InboundCore>,

    ingress_rx: mpsc::Receiver<UdpIngress>,

    flows: HashMap<UdpSourceKey, UdpFlowHandle>,

    flow_done_rx: mpsc::UnboundedReceiver<FlowDone>,
}
```

worker：

```rust
struct UdpFlowWorker {
    key: UdpSourceKey,

    inbound: Arc<InboundCore>,

    rx: mpsc::Receiver<UdpIngress>,

    datagram: Option<Arc<dyn AsyncDatagram>>,
}
```

协议 adapter：

```rust
InboundUdpSession<C>
```

只保留：

```rust
codec
udp_manager
reply_rx
```

不再持有：

```rust
flows: HashMap<...>
```

---

# 十九、改完以后数据流就会非常清晰

### SOCKS UDP

```text
socket.recv
   ↓
decode
   ↓
manager.try_dispatch
   ↓
立即继续 recv
```

### TUN

```text
smoltcp packet
   ↓
manager.try_dispatch
   ↓
立即继续 poll TUN
```

### worker

```text
packet
  ↓
route
  ↓
open outbound
  ↓
send
  ↕
recv
```

### reply

```text
worker
  ↓
ReplySink
  ↓
protocol queue / proxy_output_tx
  ↓
client
```

---

# 二十、这样第 2、3、4 点分别怎么解决

### 2. UDP 阻塞

以前：

```text
session
  ↓
handle_packet.await
  ↓
所有流停止
```

以后：

```text
session
  ↓
try_send
  ↓
立刻返回
```

某一个：

```text
flow worker.await
```

只影响自己。

---

### 3. Flow ownership

以前：

```text
每个 session
  └ HashMap
```

以后：

```text
InboundUdpManager
  └ HashMap<UdpSourceKey, FlowHandle>
```

更接近 Go：

```text
nat.Table
  └ SourceControl
```

full-cone / migrate / route cache 都自然有归属。

---

### 4. Backpressure

以前混着来：

```text
有些 send.await
有些 try_send
有些直接 async IO
```

以后明确：

```text
UDP data:
    queue full = drop

control:
    guaranteed delivery
```

这样才不会出现：

> 某个 UDP consumer 慢了一点，反向把 TUN reader 卡住，然后 TCP 都开始抖。

---

## 我会建议实际按这个顺序改

1. 先把 `InboundUdpSession::flows` 去掉，引入共享 `InboundUdpManager`。
2. `InboundUdpManager::dispatch()` 只允许 `try_send`，绝不 async。
3. 实现 per-source `UdpFlowWorker`，把 `open_datagram/send/recv` 搬进去。
4. 把 reply 改成 `ReplySink`。
5. 把 idle cleanup 从全局扫描改成 flow worker 自己的 timer。
6. 再把 TUN UDP 也接到同一个 manager。
7. 最后把 DNS async interception 接进这个流水线。

**尤其第一阶段先别碰太多协议层。** 只要 SOCKS5 UDP + TUN 两条能共用 manager 并通过测试，整体骨架就立住了。之后 Yuubinsya/TProxy 只是 adapter，代码会轻松很多。
