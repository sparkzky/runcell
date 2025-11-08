use std::{
    fmt, io,
    io::{Read, Result, Write},
    mem,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use nix::unistd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};

fn set_nonblocking(fd: RawFd) {
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
    }
}

struct StreamFd(RawFd);

impl io::Read for &StreamFd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unistd::read(self.0, buf) {
            Ok(l) => Ok(l),
            Err(e) => Err(e.into()),
        }
    }
}

impl io::Write for &StreamFd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match unistd::write(self.0, buf) {
            Ok(l) => Ok(l),
            Err(e) => Err(e.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamFd {
    fn close(&mut self) -> io::Result<()> {
        match unistd::close(self.0) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for StreamFd {
    fn drop(&mut self) {
        self.close().ok();
    }
}

impl AsRawFd for StreamFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

pub struct PipeStream(AsyncFd<StreamFd>);

impl PipeStream {
    pub fn new(fd: RawFd) -> Result<Self> {
        set_nonblocking(fd);
        Ok(Self(AsyncFd::new(StreamFd(fd))?))
    }

    pub fn from_fd(fd: RawFd) -> Self {
        unsafe { Self::from_raw_fd(fd) }
    }
}

impl AsRawFd for PipeStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for PipeStream {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.as_raw_fd();
        mem::forget(self);
        fd
    }
}

impl FromRawFd for PipeStream {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self::new(fd).unwrap()
    }
}

impl fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PipeStream({})", self.as_raw_fd())
    }
}

impl AsyncRead for PipeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let b;
        unsafe {
            b = &mut *(buf.unfilled_mut() as *mut [mem::MaybeUninit<u8>] as *mut [u8]);
        };

        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;

            match guard.try_io(|inner| inner.get_ref().read(b)) {
                Ok(Ok(n)) => {
                    unsafe {
                        buf.assume_init(n);
                    }
                    buf.advance(n);
                    return Ok(()).into();
                }
                Ok(Err(e)) => return Err(e).into(),
                Err(_would_block) => {
                    continue;
                }
            }
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 对于管道来说，关闭写端的唯一正确方法是 drop 这个 PipeStream，这会触发
        // StreamFd 的 Drop 实现，进而调用 unistd::close 关闭文件描述符。如果在 shutdown
        // 时就关闭了 fd，而 PipeStream
        // 对象本身还存在，就会导致状态不一致，并可能影响到共享同一个 fd
        // 的其他实例（如下面的测试用例所示）
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use nix::fcntl::OFlag;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    // Shutdown should never close the inner fd.
    async fn test_pipestream_shutdown() {
        let (_, wfd1) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        let mut writer1 = PipeStream::new(wfd1).unwrap();

        // if close fd in shutdown, the fd will be reused
        // and the test will failed
        // 调用 writer1.shutdown().await。测试的关键点在于：
        // 如果 shutdown 错误地关闭了 wfd1，那么这个文件描述符会被操作系统回收。
        // 那么再创建一个新的管道，得到的读端 rfd2 的文件描述符可能会与刚刚被关闭的
        // wfd1 相同（因为操作系统会重用文件描述符编号）。
        let _ = writer1.shutdown().await.unwrap();

        // 可以在这里显式删除这个 fd，然后这个测例就会阻塞
        // let _ = unistd::close(wfd1);

        let (rfd2, wfd2) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap(); // reuse fd number, rfd2 == wfd1

        let mut reader2 = PipeStream::new(rfd2).unwrap();
        let mut writer2 = PipeStream::new(wfd2).unwrap();

        // deregister writer1, then reader2 which has the same fd will be deregistered
        // from epoll
        drop(writer1);

        let _ = writer2.write(b"1").await;

        let mut content = vec![0u8; 1];
        // Will Block here if shutdown close the fd.
        let _ = reader2.read(&mut content).await;
    }
}
