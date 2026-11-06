//! Process signals: reload (SIGHUP on Unix; none on Windows, where `credstore reload` is
//! the only trigger) and terminate (Ctrl-C everywhere, SIGTERM on Unix).

use crate::OsResult;

pub struct ReloadSignal {
    #[cfg(unix)]
    inner: tokio::signal::unix::Signal,
}

impl ReloadSignal {
    pub fn new() -> OsResult<Self> {
        Ok(Self {
            #[cfg(unix)]
            inner: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    /// Wait for the next reload request.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            if self.inner.recv().await.is_none() {
                std::future::pending::<()>().await;
            }
        }
        #[cfg(windows)]
        std::future::pending::<()>().await;
    }
}

/// Resolves on Ctrl-C, or SIGTERM on Unix.
pub async fn terminate() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(t) => t,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
