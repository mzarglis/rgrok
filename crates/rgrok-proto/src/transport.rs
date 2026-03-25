use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::{AsyncRead, AsyncWrite, SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Transport abstraction layer (Phase 6 prep)
// ---------------------------------------------------------------------------

/// A single bidirectional stream within a multiplexed connection.
/// Both yamux::Stream and (future) QUIC streams implement this.
pub trait TunnelStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Blanket impl: anything that is AsyncRead + AsyncWrite + Unpin + Send is a TunnelStream.
impl<T> TunnelStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// A multiplexed connection that can open/accept independent streams.
/// Both WebSocket+yamux and (future) QUIC implement this.
#[async_trait::async_trait]
pub trait TunnelTransport: Send + Sync + 'static {
    /// Open a new outbound stream (client → server)
    async fn open_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>>;

    /// Accept the next inbound stream (server ← client)
    async fn accept_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>>;

    /// Human-readable label for logs ("websocket" | "quic")
    fn kind(&self) -> &'static str;
}

/// WebSocket+yamux implementation of TunnelTransport.
/// Wraps the existing YamuxControl + inbound stream receiver.
pub struct YamuxTransport {
    control: YamuxControl,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<yamux::Stream>>,
}

impl YamuxTransport {
    pub fn new(control: YamuxControl, inbound_rx: mpsc::Receiver<yamux::Stream>) -> Self {
        Self {
            control,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        }
    }
}

#[async_trait::async_trait]
impl TunnelTransport for YamuxTransport {
    async fn open_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let stream = self.control.open_stream().await
            .map_err(|e| anyhow::anyhow!("yamux open_stream: {}", e))?;
        // Wrap yamux::Stream (futures AsyncRead/Write) into tokio AsyncRead/Write
        let compat = tokio_util::compat::FuturesAsyncReadCompatExt::compat(stream);
        Ok(Box::new(compat))
    }

    async fn accept_stream(&self) -> anyhow::Result<Box<dyn TunnelStream>> {
        let mut rx = self.inbound_rx.lock().await;
        let stream = rx.recv().await
            .ok_or_else(|| anyhow::anyhow!("yamux connection closed"))?;
        let compat = tokio_util::compat::FuturesAsyncReadCompatExt::compat(stream);
        Ok(Box::new(compat))
    }

    fn kind(&self) -> &'static str {
        "websocket"
    }
}

/// Adapter that bridges a WebSocket stream to futures::AsyncRead + AsyncWrite
/// so it can be used as the underlying I/O for yamux::Connection.
pub struct WsCompat<S> {
    inner: S,
    read_buf: BytesMut,
}

impl<S> WsCompat<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
        }
    }
}

impl<S> AsyncRead for WsCompat<S>
where
    S: futures::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(buf.len(), self.read_buf.len());
            buf[..len].copy_from_slice(&self.read_buf.split_to(len));
            return Poll::Ready(Ok(len));
        }

        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                let data = match msg {
                    tokio_tungstenite::tungstenite::Message::Binary(data) => data,
                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                        return Poll::Ready(Ok(0));
                    }
                    _ => return Poll::Ready(Ok(0)),
                };
                if data.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                let len = std::cmp::min(buf.len(), data.len());
                buf[..len].copy_from_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WsCompat<S>
where
    S: futures::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {
                let msg = tokio_tungstenite::tungstenite::Message::Binary(buf.to_vec().into());
                match self.inner.start_send_unpin(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner
            .poll_flush_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner
            .poll_close_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// A handle to the yamux session that allows opening outbound streams.
/// Multiple clones can be held concurrently.
#[derive(Clone)]
pub struct YamuxControl {
    open_tx: mpsc::Sender<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>>,
}

impl YamuxControl {
    /// Open a new outbound yamux stream.
    pub async fn open_stream(&self) -> Result<yamux::Stream, yamux::ConnectionError> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| yamux::ConnectionError::Closed)?;
        rx.await.map_err(|_| yamux::ConnectionError::Closed)?
    }
}

/// Start the yamux driver task. Returns:
/// - `YamuxControl`: for opening outbound streams
/// - `mpsc::Receiver<yamux::Stream>`: receives inbound streams
/// - `tokio::task::JoinHandle`: the driver task handle
pub fn spawn_yamux_driver<T>(
    connection: yamux::Connection<T>,
) -> (
    YamuxControl,
    mpsc::Receiver<yamux::Stream>,
    tokio::task::JoinHandle<()>,
)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (open_tx, mut open_rx) =
        mpsc::channel::<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>>(32);
    let (inbound_tx, inbound_rx) = mpsc::channel::<yamux::Stream>(32);

    let handle = tokio::spawn(async move {
        let mut conn = connection;
        let mut pending_reply: Option<
            oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>,
        > = None;

        loop {
            // Check for new open requests (non-blocking)
            if pending_reply.is_none() {
                match open_rx.try_recv() {
                    Ok(reply) => pending_reply = Some(reply),
                    Err(_) => {}
                }
            }

            // Drive the connection: poll both inbound and outbound in a single poll_fn
            // so yamux can make progress on all fronts simultaneously.
            enum DriverEvent {
                Inbound(yamux::Stream),
                InboundError,
                InboundDone,
                OutboundReady(Result<yamux::Stream, yamux::ConnectionError>),
                OpenRequest(oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>),
            }

            let event = std::future::poll_fn(|cx| {
                // Drive the connection first (flushes outgoing frames, reads incoming)
                let inbound = conn.poll_next_inbound(cx);

                // Try outbound if we have a pending request
                if pending_reply.is_some() {
                    if let Poll::Ready(result) = conn.poll_new_outbound(cx) {
                        return Poll::Ready(DriverEvent::OutboundReady(result));
                    }
                }

                // Check for new open requests
                if pending_reply.is_none() {
                    if let Poll::Ready(Some(reply)) = open_rx.poll_recv(cx) {
                        return Poll::Ready(DriverEvent::OpenRequest(reply));
                    }
                }

                // Return inbound result
                match inbound {
                    Poll::Ready(Some(Ok(stream))) => Poll::Ready(DriverEvent::Inbound(stream)),
                    Poll::Ready(Some(Err(e))) => {
                        tracing::warn!("yamux inbound error: {}", e);
                        Poll::Ready(DriverEvent::InboundError)
                    }
                    Poll::Ready(None) => Poll::Ready(DriverEvent::InboundDone),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;

            match event {
                DriverEvent::Inbound(stream) => {
                    if inbound_tx.send(stream).await.is_err() {
                        break;
                    }
                }
                DriverEvent::InboundError | DriverEvent::InboundDone => break,
                DriverEvent::OutboundReady(result) => {
                    if let Some(reply) = pending_reply.take() {
                        let _ = reply.send(result);
                    }
                }
                DriverEvent::OpenRequest(reply) => {
                    pending_reply = Some(reply);
                }
            }
        }
    });

    (YamuxControl { open_tx }, inbound_rx, handle)
}

/// Helper to read a length-prefixed MessagePack message from a yamux stream.
pub async fn read_msg_from_stream<T: serde::de::DeserializeOwned>(
    stream: &mut yamux::Stream,
) -> anyhow::Result<T> {
    use futures::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > 1_048_576 {
        anyhow::bail!("message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    let msg = crate::decode_msg(&buf)?;
    Ok(msg)
}

/// Helper to write a length-prefixed MessagePack message to a yamux stream.
pub async fn write_msg_to_stream<T: serde::Serialize>(
    stream: &mut yamux::Stream,
    msg: &T,
) -> anyhow::Result<()> {
    use futures::AsyncWriteExt;

    let data = crate::encode_msg(msg)?;
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}

/// Default yamux configuration tuned for tunnel use
pub fn yamux_config() -> yamux::Config {
    yamux::Config::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    /// Create a yamux stream pair using spawn_yamux_driver for proper bidirectional driving.
    /// Returns (client_stream, server_stream) plus handles that must be kept alive.
    ///
    /// NOTE: yamux's `poll_new_outbound` creates a stream locally without sending any frame
    /// to the remote. The SYN flag is only sent with the first data frame. So we must write
    /// a handshake byte to trigger the SYN and let the server see the inbound stream.
    async fn open_yamux_stream_pair() -> (
        yamux::Stream,
        yamux::Stream,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures::{AsyncReadExt as _, AsyncWriteExt as _};

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let client_conn = yamux::Connection::new(
            client_io.compat(),
            yamux_config(),
            yamux::Mode::Client,
        );
        let server_conn = yamux::Connection::new(
            server_io.compat(),
            yamux_config(),
            yamux::Mode::Server,
        );

        let (client_ctrl, _client_rx, client_handle) = spawn_yamux_driver(client_conn);
        let (_server_ctrl, mut server_rx, server_handle) = spawn_yamux_driver(server_conn);

        let mut client_stream = client_ctrl.open_stream().await.unwrap();

        // Write a handshake byte to trigger the SYN frame, then read it on the server side.
        let (_, server_stream) = tokio::join!(
            async {
                client_stream.write_all(&[0xFF]).await.unwrap();
                client_stream.flush().await.unwrap();
            },
            async {
                let mut s = server_rx.recv().await.unwrap();
                let mut buf = [0u8; 1];
                s.read_exact(&mut buf).await.unwrap();
                s
            }
        );

        (client_stream, server_stream, client_handle, server_handle)
    }

    // -----------------------------------------------------------------------
    // 1. Framing/Codec: write_msg_to_stream + read_msg_from_stream round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_msg_round_trip_ping() {
        let (mut client_stream, mut server_stream, _h1, _h2) = open_yamux_stream_pair().await;

        let original = crate::messages::ClientMsg::Ping { seq: 42 };
        write_msg_to_stream(&mut client_stream, &original).await.unwrap();

        let decoded: crate::messages::ClientMsg =
            read_msg_from_stream(&mut server_stream).await.unwrap();
        match decoded {
            crate::messages::ClientMsg::Ping { seq } => assert_eq!(seq, 42),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_msg_round_trip_server_msg() {
        let (mut client_stream, mut server_stream, _h1, _h2) = open_yamux_stream_pair().await;

        let original = crate::messages::ServerMsg::AuthOk {
            session_id: "sess-123".to_string(),
        };
        // Server writes, client reads (reverse direction on same stream pair)
        write_msg_to_stream(&mut server_stream, &original).await.unwrap();

        let decoded: crate::messages::ServerMsg =
            read_msg_from_stream(&mut client_stream).await.unwrap();
        match decoded {
            crate::messages::ServerMsg::AuthOk { session_id } => {
                assert_eq!(session_id, "sess-123");
            }
            other => panic!("expected AuthOk, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_msg_round_trip_multiple_messages() {
        let (mut client_stream, mut server_stream, _h1, _h2) = open_yamux_stream_pair().await;

        // Send several messages in sequence
        for i in 0..10u64 {
            let msg = crate::messages::ClientMsg::Ping { seq: i };
            write_msg_to_stream(&mut client_stream, &msg).await.unwrap();
        }

        // Read them back in order
        for i in 0..10u64 {
            let decoded: crate::messages::ClientMsg =
                read_msg_from_stream(&mut server_stream).await.unwrap();
            match decoded {
                crate::messages::ClientMsg::Ping { seq } => assert_eq!(seq, i),
                other => panic!("expected Ping {{ seq: {} }}, got {:?}", i, other),
            }
        }
    }

    // -----------------------------------------------------------------------
    // 2. WsCompat buffer logic
    // -----------------------------------------------------------------------

    /// A mock WebSocket stream that yields pre-loaded Binary messages.
    struct MockWsStream {
        messages: std::collections::VecDeque<
            Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        >,
        sent: Vec<Vec<u8>>,
    }

    impl MockWsStream {
        fn new(data: Vec<Vec<u8>>) -> Self {
            let messages = data
                .into_iter()
                .map(|d| {
                    Ok(tokio_tungstenite::tungstenite::Message::Binary(
                        d.into(),
                    ))
                })
                .collect();
            Self {
                messages,
                sent: Vec::new(),
            }
        }
    }

    impl futures::Stream for MockWsStream {
        type Item = Result<
            tokio_tungstenite::tungstenite::Message,
            tokio_tungstenite::tungstenite::Error,
        >;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match self.messages.pop_front() {
                Some(msg) => Poll::Ready(Some(msg)),
                None => Poll::Ready(None),
            }
        }
    }

    impl futures::Sink<tokio_tungstenite::tungstenite::Message> for MockWsStream {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(
            mut self: Pin<&mut Self>,
            item: tokio_tungstenite::tungstenite::Message,
        ) -> Result<(), Self::Error> {
            if let tokio_tungstenite::tungstenite::Message::Binary(data) = item {
                self.sent.push(data.to_vec());
            }
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_wscompat_small_read_buffers_large_message() {
        // A single large WS message (16 bytes) read in small chunks (4 bytes at a time).
        let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mock = MockWsStream::new(vec![data.clone()]);
        let mut ws = WsCompat::new(mock);

        let mut collected = Vec::new();
        let mut small_buf = [0u8; 4];
        loop {
            let n = futures::AsyncReadExt::read(&mut ws, &mut small_buf).await.unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&small_buf[..n]);
        }
        assert_eq!(collected, data);
    }

    #[tokio::test]
    async fn test_wscompat_multiple_messages_sequential_reads() {
        // Two WS messages read sequentially; data should not be lost.
        let msg1 = vec![10, 20, 30];
        let msg2 = vec![40, 50, 60, 70];
        let mock = MockWsStream::new(vec![msg1.clone(), msg2.clone()]);
        let mut ws = WsCompat::new(mock);

        let mut collected = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = futures::AsyncReadExt::read(&mut ws, &mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
        }
        let mut expected = msg1;
        expected.extend_from_slice(&msg2);
        assert_eq!(collected, expected);
    }

    #[tokio::test]
    async fn test_wscompat_read_exact_size() {
        // Buffer is exactly the same size as the message: no leftover in read_buf.
        let data = vec![0xAA, 0xBB, 0xCC];
        let mock = MockWsStream::new(vec![data.clone()]);
        let mut ws = WsCompat::new(mock);

        let mut buf = [0u8; 3];
        let n = futures::AsyncReadExt::read(&mut ws, &mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf[..], &data[..]);
        // Internal buffer should be empty now
        assert!(ws.read_buf.is_empty());
    }

    #[tokio::test]
    async fn test_wscompat_write_sends_binary() {
        let mock = MockWsStream::new(vec![]);
        let mut ws = WsCompat::new(mock);

        let payload = b"hello world";
        let n = futures::AsyncWriteExt::write(&mut ws, payload).await.unwrap();
        assert_eq!(n, payload.len());

        // Verify the mock captured the binary message
        assert_eq!(ws.inner.sent.len(), 1);
        assert_eq!(ws.inner.sent[0], payload.to_vec());
    }

    #[tokio::test]
    async fn test_wscompat_close_message_returns_eof() {
        // A Close message should yield 0 bytes (EOF).
        let close_msg = tokio_tungstenite::tungstenite::Message::Close(None);
        let mock = MockWsStream {
            messages: vec![Ok(close_msg)].into_iter().collect(),
            sent: Vec::new(),
        };
        let mut ws = WsCompat::new(mock);

        let mut buf = [0u8; 32];
        let n = futures::AsyncReadExt::read(&mut ws, &mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    // -----------------------------------------------------------------------
    // 3. YamuxTransport trait implementation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_yamux_transport_kind() {
        let (_ctrl, rx, _h) = {
            let (io1, _io2) = tokio::io::duplex(1024);
            let conn = yamux::Connection::new(
                io1.compat(),
                yamux_config(),
                yamux::Mode::Client,
            );
            spawn_yamux_driver(conn)
        };

        let transport = YamuxTransport::new(_ctrl, rx);
        assert_eq!(transport.kind(), "websocket");
    }

    /// Helper: set up a YamuxTransport pair backed by spawn_yamux_driver,
    /// suitable for testing `open_stream` / `accept_stream` concurrently.
    fn setup_transport_pair() -> (YamuxTransport, YamuxTransport) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let client_conn = yamux::Connection::new(
            client_io.compat(),
            yamux_config(),
            yamux::Mode::Client,
        );
        let server_conn = yamux::Connection::new(
            server_io.compat(),
            yamux_config(),
            yamux::Mode::Server,
        );

        let (client_ctrl, client_rx, _h1) = spawn_yamux_driver(client_conn);
        let (server_ctrl, server_rx, _h2) = spawn_yamux_driver(server_conn);

        (
            YamuxTransport::new(client_ctrl, client_rx),
            YamuxTransport::new(server_ctrl, server_rx),
        )
    }

    #[tokio::test]
    async fn test_yamux_transport_open_and_accept_stream() {
        let (client_transport, server_transport) = setup_transport_pair();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Open stream on client (returns immediately — SYN is deferred until first write)
        let mut client_stream = client_transport.open_stream().await.expect("open failed");

        // Write data (triggers SYN) while server accepts the new stream
        let accept_task = tokio::spawn(async move {
            server_transport.accept_stream().await.expect("accept failed")
        });

        client_stream.write_all(b"hello from client").await.unwrap();
        client_stream.flush().await.unwrap();

        let mut server_stream = accept_task.await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from client");
    }

    #[tokio::test]
    async fn test_yamux_transport_bidirectional() {
        let (client_transport, server_transport) = setup_transport_pair();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Server opens a stream (returns immediately — SYN is deferred until first write)
        let mut server_stream = server_transport.open_stream().await.expect("open failed");

        // Write data (triggers SYN) while client accepts the new stream
        let accept_task = tokio::spawn(async move {
            client_transport.accept_stream().await.expect("accept failed")
        });

        server_stream.write_all(b"server says hi").await.unwrap();
        server_stream.flush().await.unwrap();

        let mut client_stream = accept_task.await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = client_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"server says hi");
    }
}
