use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf as _, BytesMut};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;

pub struct WsBytes<S> {
    ws: S,
    buf: BytesMut,
}

pub type WsByteStream = WsBytes<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>;

pub fn wrap_ws(ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> WsByteStream {
    WsBytes {
        ws,
        buf: BytesMut::new(),
    }
}

impl<S> AsyncRead for WsBytes<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let len = self.buf.len().min(buf.remaining());
                buf.put_slice(&self.buf[..len]);
                self.buf.advance(len);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => self.buf.extend_from_slice(&data),
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsBytes<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => return Poll::Pending,
        }
        if let Err(error) = Pin::new(&mut self.ws).start_send(Message::Binary(buf.to_vec().into()))
        {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        let _ = Pin::new(&mut self.ws).poll_flush(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
