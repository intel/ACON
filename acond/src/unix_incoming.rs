// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use futures::{ready, Stream};
use std::{
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::net::UnixListener;

mod unix_stream {
    use super::*;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{
            unix::{SocketAddr, UCred},
            UnixStream as TokUnixStream,
        },
    };
    use tonic::transport::server::Connected;

    #[derive(Debug)]
    pub struct UnixStream(pub TokUnixStream);

    impl Connected for UnixStream {
        type ConnectInfo = UnixConnectInfo;
        fn connect_info(&self) -> Self::ConnectInfo {
            UnixConnectInfo {
                peer_addr: self.0.peer_addr().ok().map(Arc::new),
                peer_cred: self.0.peer_cred().ok(),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct UnixConnectInfo {
        pub peer_addr: Option<Arc<SocketAddr>>,
        pub peer_cred: Option<UCred>,
    }

    impl AsyncRead for UnixStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for UnixStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

#[derive(Debug)]
pub struct UnixIncoming {
    inner: UnixListener,
}

impl UnixIncoming {
    pub fn new(listener: UnixListener) -> Self {
        Self { inner: listener }
    }
}

impl Stream for UnixIncoming {
    type Item = std::io::Result<unix_stream::UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (socket, _) = ready!(self.inner.poll_accept(cx))?;
        Poll::Ready(Some(Ok(unix_stream::UnixStream(socket))))
    }
}

impl AsRawFd for UnixIncoming {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}
