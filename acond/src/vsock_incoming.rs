// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use futures::{ready, Stream};
use std::{
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};
use tokio_vsock::VsockListener;

mod vsock_stream {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_vsock::{VsockAddr, VsockStream as TokVsockStream};
    use tonic::transport::server::Connected;

    #[derive(Debug)]
    pub struct VsockStream(pub TokVsockStream);

    impl Connected for VsockStream {
        type ConnectInfo = VsockConnectInfo;
        fn connect_info(&self) -> Self::ConnectInfo {
            VsockConnectInfo {
                peer_addr: self.0.peer_addr().ok().map(Arc::new),
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct VsockConnectInfo {
        pub peer_addr: Option<Arc<VsockAddr>>,
    }

    impl AsyncRead for VsockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for VsockStream {
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
pub struct VsockIncoming {
    inner: VsockListener,
}

impl VsockIncoming {
    pub fn new(listener: VsockListener) -> Self {
        Self { inner: listener }
    }
}

impl Stream for VsockIncoming {
    type Item = std::io::Result<vsock_stream::VsockStream>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (socket, _) = ready!(self.inner.poll_accept(cx))?;
        Poll::Ready(Some(Ok(vsock_stream::VsockStream(socket))))
    }
}

impl AsRawFd for VsockIncoming {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}
