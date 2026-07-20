//! Managed subprocess primitives for mesh backends owned by WutherCore.
//!
//! This module is deliberately **not** an adapter for an already-running
//! external daemon. A [`ManagedChild`] can only be created by spawning a
//! [`ManagedProcessSpec`], so dropping it cannot accidentally terminate a
//! system-owned `tailscaled` or another process discovered by PID.
//!
//! `command-group` supplies the platform boundary: a POSIX process group on
//! Unix and a Job Object on Windows. All forced termination therefore applies
//! to the complete tree created by the managed daemon.

use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    fmt,
    future::Future,
    io::{self, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use command_group::{AsyncCommandGroup, AsyncGroupChild};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::ChildStdin,
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const REDACTION_MARKER: &[u8] = b"[REDACTED]";
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// A clonable registry of values which must never be exposed by managed
/// process diagnostics.
///
/// The process launcher automatically registers the program argv and every
/// explicitly configured environment value. Callers additionally register
/// credentials, tokens, or secret-file contents. Empty values are ignored.
/// Registered bytes are zeroized when the final [`Redactor`] clone is dropped.
#[derive(Clone, Default)]
pub struct Redactor {
    values: Arc<RwLock<Vec<Zeroizing<Vec<u8>>>>>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an exact byte sequence as sensitive.
    pub fn register(&self, value: impl AsRef<[u8]>) {
        let value = value.as_ref();
        if value.is_empty() {
            return;
        }
        let mut values = self.values.write().unwrap_or_else(|e| e.into_inner());
        if values.iter().any(|known| known.as_slice() == value) {
            return;
        }
        values.push(Zeroizing::new(value.to_vec()));
        // Prefer the longest match when one secret is a prefix of another.
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    }

    fn register_os(&self, value: &OsStr) {
        self.register(value.to_string_lossy().as_bytes());
    }

    /// Return a redacted representation suitable for an error or log line.
    pub fn redact(&self, value: impl AsRef<[u8]>) -> String {
        String::from_utf8_lossy(&self.redact_bytes(value.as_ref())).into_owned()
    }

    fn redact_bytes(&self, value: &[u8]) -> Vec<u8> {
        let mut stream = StreamingRedactor::new(self.clone());
        stream.push(value, true)
    }

    fn match_at_start(&self, pending: &[u8]) -> RedactionMatch {
        let values = self.values.read().unwrap_or_else(|e| e.into_inner());
        let mut potential_prefix = false;
        for value in values.iter() {
            let value = value.as_slice();
            if pending.starts_with(value) {
                return RedactionMatch::Complete(value.len());
            }
            if value.starts_with(pending) {
                potential_prefix = true;
            }
        }
        if potential_prefix {
            RedactionMatch::PotentialPrefix
        } else {
            RedactionMatch::None
        }
    }

    fn len(&self) -> usize {
        self.values.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("registered_values", &self.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedactionMatch {
    Complete(usize),
    PotentialPrefix,
    None,
}

/// Streaming exact-match redaction. Bytes which might be the prefix of a
/// secret are retained until the next chunk, preventing a credential split
/// across two pipe reads from escaping.
struct StreamingRedactor {
    redactor: Redactor,
    pending: Vec<u8>,
}

impl StreamingRedactor {
    fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            pending: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8], eof: bool) -> Vec<u8> {
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::with_capacity(bytes.len());
        let mut consumed = 0;
        while consumed < self.pending.len() {
            match self.redactor.match_at_start(&self.pending[consumed..]) {
                RedactionMatch::Complete(len) => {
                    consumed += len;
                    output.extend_from_slice(REDACTION_MARKER);
                }
                RedactionMatch::PotentialPrefix if !eof => break,
                RedactionMatch::PotentialPrefix => {
                    // A process may terminate after writing only a prefix of a
                    // credential. Treat that fragment as sensitive as well.
                    consumed = self.pending.len();
                    output.extend_from_slice(REDACTION_MARKER);
                }
                RedactionMatch::None => {
                    output.push(self.pending[consumed]);
                    consumed += 1;
                }
            }
        }
        if consumed != 0 {
            self.pending.drain(..consumed);
        }
        output
    }
}

/// Bounded capture settings for each output stream.
#[derive(Debug, Clone, Copy)]
pub struct OutputPolicy {
    /// Retain at most this many already-redacted bytes per stream.
    pub max_bytes_per_stream: usize,
    /// Size of each asynchronous pipe read.
    pub read_chunk_bytes: usize,
    /// Maximum time spent draining pipes after the process group has exited.
    pub drain_timeout: Duration,
}

impl Default for OutputPolicy {
    fn default() -> Self {
        Self {
            max_bytes_per_stream: 64 * 1024,
            read_chunk_bytes: 4096,
            drain_timeout: Duration::from_millis(250),
        }
    }
}

/// A bounded, redacted stream snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedLog {
    pub text: String,
    pub truncated: bool,
    pub dropped_bytes: usize,
}

/// Current stdout and stderr snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessLogs {
    pub stdout: CapturedLog,
    pub stderr: CapturedLog,
}

#[derive(Debug)]
struct BoundedLog {
    bytes: VecDeque<u8>,
    max_bytes: usize,
    dropped_bytes: usize,
}

impl BoundedLog {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(max_bytes.min(4096)),
            max_bytes,
            dropped_bytes: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.max_bytes == 0 {
            self.dropped_bytes = self.dropped_bytes.saturating_add(bytes.len());
            return;
        }
        self.bytes.extend(bytes.iter().copied());
        while self.bytes.len() > self.max_bytes {
            self.bytes.pop_front();
            self.dropped_bytes = self.dropped_bytes.saturating_add(1);
        }
    }

    fn snapshot(&self) -> CapturedLog {
        let bytes = self.bytes.iter().copied().collect::<Vec<_>>();
        CapturedLog {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            truncated: self.dropped_bytes != 0,
            dropped_bytes: self.dropped_bytes,
        }
    }
}

type SharedLog = Arc<Mutex<BoundedLog>>;

async fn capture_output<R>(mut reader: R, redactor: Redactor, sink: SharedLog, chunk_size: usize)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; chunk_size.max(1)];
    let mut streaming = StreamingRedactor::new(redactor);
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                let tail = streaming.push(&[], true);
                sink.lock().unwrap_or_else(|e| e.into_inner()).append(&tail);
                break;
            }
            Ok(read) => {
                let redacted = streaming.push(&buffer[..read], false);
                sink.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .append(&redacted);
            }
            Err(_) => {
                let tail = streaming.push(&[], true);
                sink.lock().unwrap_or_else(|e| e.into_inner()).append(&tail);
                break;
            }
        }
    }
}

/// A securely-created temporary file containing a secret.
///
/// The file name is random and creation is exclusive. On Unix the mode is
/// explicitly forced to `0600` before contents are written. Windows uses
/// `tempfile`'s exclusive file creation in the current user's temporary
/// directory; its confidentiality boundary is the ACL inherited from that
/// directory. Installations requiring a stricter Windows DACL must supply a
/// pre-hardened temporary directory through [`SecretFile::create_in`].
///
/// The contents are registered with the supplied [`Redactor`], are never
/// returned by this API, and therefore do not need to appear in argv. Dropping
/// the value removes the temporary file through [`NamedTempFile`].
pub struct SecretFile {
    file: NamedTempFile,
}

impl SecretFile {
    pub fn create(contents: impl AsRef<[u8]>, redactor: &Redactor) -> io::Result<Self> {
        Self::create_in(std::env::temp_dir(), contents, redactor)
    }

    pub fn create_in(
        directory: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        redactor: &Redactor,
    ) -> io::Result<Self> {
        let contents = contents.as_ref();
        redactor.register(contents);
        let mut file = TempFileBuilder::new()
            .prefix("wuther-mesh-secret-")
            .tempfile_in(directory)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        file.as_file_mut().write_all(contents)?;
        file.as_file_mut().flush()?;
        Ok(Self { file })
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }

    /// Explicitly close and delete the file, reporting deletion failures.
    pub fn close(self) -> io::Result<()> {
        self.file.close()
    }
}

impl fmt::Debug for SecretFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFile")
            .field("path", &"[temporary secret path]")
            .finish()
    }
}

/// Error returned by a readiness or graceful-shutdown hook.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct ProcessHookError {
    message: String,
}

impl ProcessHookError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Poll a process hook across an unwind boundary without retaining or
/// formatting its panic payload.
///
/// The constructor is also guarded by [`catch_hook_future`], covering custom
/// trait implementations which panic before returning their future.
struct CatchHookUnwind<F> {
    inner: Pin<Box<F>>,
}

impl<F> CatchHookUnwind<F> {
    fn new(future: F) -> Self {
        Self {
            inner: Box::pin(future),
        }
    }
}

impl<F: Future> Future for CatchHookUnwind<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match catch_unwind(AssertUnwindSafe(|| this.inner.as_mut().poll(context))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

fn catch_hook_future<F>(create: impl FnOnce() -> F) -> Result<CatchHookUnwind<F>, ()>
where
    F: Future,
{
    catch_unwind(AssertUnwindSafe(create))
        .map(CatchHookUnwind::new)
        .map_err(|_| ())
}

/// Information available to a readiness probe.
#[derive(Debug, Clone)]
pub struct ReadinessContext {
    pid: u32,
    started_at: Instant,
    cancellation: CancellationToken,
}

impl ReadinessContext {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

/// Asynchronous readiness contract for a newly spawned daemon.
///
/// Implementations may retry internally, but should observe the cancellation
/// token in [`ReadinessContext`]. The manager concurrently checks for early
/// process exit and enforces the configured readiness timeout.
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    async fn wait_until_ready(&self, context: ReadinessContext) -> Result<(), ProcessHookError>;
}

#[derive(Debug, Default)]
pub struct ImmediateReadiness;

#[async_trait]
impl ReadinessProbe for ImmediateReadiness {
    async fn wait_until_ready(&self, _context: ReadinessContext) -> Result<(), ProcessHookError> {
        Ok(())
    }
}

/// A handle exposed to a graceful-shutdown hook.
#[derive(Clone)]
pub struct ShutdownContext {
    pid: u32,
    stdin: Arc<tokio::sync::Mutex<Option<ChildStdin>>>,
    cancellation: CancellationToken,
}

impl ShutdownContext {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Write a protocol-specific shutdown command to the managed daemon.
    pub async fn write_stdin(&self, bytes: &[u8]) -> io::Result<()> {
        let mut stdin = self.stdin.lock().await;
        let Some(stdin) = stdin.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "managed process stdin is closed",
            ));
        };
        stdin.write_all(bytes).await?;
        stdin.flush().await
    }

    /// Close stdin after a shutdown command has been written.
    pub async fn close_stdin(&self) {
        self.stdin.lock().await.take();
    }
}

impl fmt::Debug for ShutdownContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShutdownContext")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

/// Protocol-specific graceful shutdown. Returning does not imply the process
/// has exited; the manager still waits up to `shutdown_timeout`, then kills and
/// reaps the complete process group.
#[async_trait]
pub trait GracefulShutdown: Send + Sync {
    async fn shutdown(&self, context: ShutdownContext) -> Result<(), ProcessHookError>;
}

#[derive(Debug, Default)]
pub struct NoopGracefulShutdown;

#[async_trait]
impl GracefulShutdown for NoopGracefulShutdown {
    async fn shutdown(&self, _context: ShutdownContext) -> Result<(), ProcessHookError> {
        Ok(())
    }
}

/// A graceful shutdown hook which writes a fixed command to child stdin.
pub struct StdinGracefulShutdown {
    bytes: Zeroizing<Vec<u8>>,
    close_after_write: bool,
}

impl StdinGracefulShutdown {
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes.as_ref().to_vec()),
            close_after_write: true,
        }
    }

    pub fn keep_stdin_open(mut self) -> Self {
        self.close_after_write = false;
        self
    }
}

impl fmt::Debug for StdinGracefulShutdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdinGracefulShutdown")
            .field("bytes", &"[redacted]")
            .field("close_after_write", &self.close_after_write)
            .finish()
    }
}

#[async_trait]
impl GracefulShutdown for StdinGracefulShutdown {
    async fn shutdown(&self, context: ShutdownContext) -> Result<(), ProcessHookError> {
        context
            .write_stdin(&self.bytes)
            .await
            .map_err(|e| ProcessHookError::new(e.to_string()))?;
        if self.close_after_write {
            context.close_stdin().await;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartCondition {
    Never,
    OnFailure,
    Always,
}

/// Backoff parameters used by [`ManagedDaemon::ensure_running`].
#[derive(Debug, Clone, Copy)]
pub struct RestartPolicy {
    pub condition: RestartCondition,
    /// Number of restarts after the initial attempt.
    pub max_restarts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl RestartPolicy {
    pub const NEVER: Self = Self {
        condition: RestartCondition::Never,
        max_restarts: 0,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    };

    fn permits(self, status: Option<ExitStatus>, attempts: u32) -> bool {
        if attempts >= self.max_restarts {
            return false;
        }
        match self.condition {
            RestartCondition::Never => false,
            RestartCondition::Always => true,
            RestartCondition::OnFailure => status.map(|s| !s.success()).unwrap_or(true),
        }
    }

    fn backoff(self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let shift = (attempt - 1).min(31);
        let multiplier = 1_u32 << shift;
        self.initial_backoff
            .checked_mul(multiplier)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff)
    }
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self::NEVER
    }
}

/// Internal launch contract for a daemon owned by WutherCore.
///
/// This is intentionally not serializable user configuration. In particular,
/// hooks are executable Rust policy and secret files are live resources.
/// Authentication material must use [`Self::add_secret_file`] rather than
/// `args` or `env`: argv is observable by other local processes and `OsString`
/// environment storage cannot be reliably zeroized. The environment is
/// cleared by default; concrete adapters must explicitly allowlist every
/// variable their official daemon needs.
pub struct ManagedProcessSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub clear_env: bool,
    pub cwd: Option<PathBuf>,
    /// Readiness must be selected explicitly. Use
    /// [`ManagedProcessSpec::with_immediate_readiness`] only for programs whose
    /// successful spawn is itself a complete readiness contract.
    pub readiness: Option<Arc<dyn ReadinessProbe>>,
    pub readiness_timeout: Duration,
    pub startup_poll_interval: Duration,
    pub monitor_poll_interval: Duration,
    pub stop: Arc<dyn GracefulShutdown>,
    pub shutdown_timeout: Duration,
    /// Maximum time an explicit lifecycle operation waits for the process
    /// group reaper. The reaper remains independently owned if this deadline
    /// expires, so cancelling a caller never creates a second concurrent wait.
    pub reap_timeout: Duration,
    pub output: OutputPolicy,
    pub restart: RestartPolicy,
    redactor: Redactor,
    secret_files: Vec<SecretFile>,
}

impl ManagedProcessSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            clear_env: true,
            cwd: None,
            readiness: None,
            readiness_timeout: Duration::from_secs(30),
            startup_poll_interval: Duration::from_millis(10),
            monitor_poll_interval: Duration::from_millis(10),
            stop: Arc::new(NoopGracefulShutdown),
            shutdown_timeout: Duration::from_secs(10),
            reap_timeout: Duration::from_secs(5),
            output: OutputPolicy::default(),
            restart: RestartPolicy::NEVER,
            redactor: Redactor::new(),
            secret_files: Vec::new(),
        }
    }

    pub fn arg(&mut self, arg: impl Into<OsString>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> &mut Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn with_readiness(&mut self, readiness: Arc<dyn ReadinessProbe>) -> &mut Self {
        self.readiness = Some(readiness);
        self
    }

    pub fn with_immediate_readiness(&mut self) -> &mut Self {
        self.readiness = Some(Arc::new(ImmediateReadiness));
        self
    }

    pub fn register_secret(&self, value: impl AsRef<[u8]>) {
        self.redactor.register(value);
    }

    pub fn redactor(&self) -> Redactor {
        self.redactor.clone()
    }

    /// Create and retain a secret file for the full daemon lifecycle.
    ///
    /// Only the random path is returned. The contents are registered with the
    /// redactor and cannot be recovered through this API.
    pub fn add_secret_file(&mut self, contents: impl AsRef<[u8]>) -> io::Result<PathBuf> {
        let file = SecretFile::create(contents, &self.redactor)?;
        let path = file.path().to_path_buf();
        self.secret_files.push(file);
        Ok(path)
    }

    pub fn add_secret_file_in(
        &mut self,
        directory: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> io::Result<PathBuf> {
        let file = SecretFile::create_in(directory, contents, &self.redactor)?;
        let path = file.path().to_path_buf();
        self.secret_files.push(file);
        Ok(path)
    }

    fn register_launch_values(&self) {
        self.redactor.register_os(self.program.as_os_str());
        for arg in &self.args {
            self.redactor.register_os(arg);
        }
        for (_, value) in &self.env {
            self.redactor.register_os(value);
        }
    }
}

impl fmt::Debug for ManagedProcessSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedProcessSpec")
            .field("program", &"[redacted argv]")
            .field(
                "args",
                &format_args!("[{} redacted values]", self.args.len()),
            )
            .field("env", &format_args!("[{} redacted values]", self.env.len()))
            .field("clear_env", &self.clear_env)
            .field("cwd", &self.cwd)
            .field("readiness_configured", &self.readiness.is_some())
            .field("readiness_timeout", &self.readiness_timeout)
            .field("startup_poll_interval", &self.startup_poll_interval)
            .field("monitor_poll_interval", &self.monitor_poll_interval)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("reap_timeout", &self.reap_timeout)
            .field("output", &self.output)
            .field("restart", &self.restart)
            .field("secret_files", &self.secret_files.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedChildState {
    Starting,
    Ready,
    Stopping,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationKind {
    Exited,
    Graceful,
    Forced,
}

#[derive(Debug, Clone)]
pub struct TerminationReport {
    pub kind: TerminationKind,
    pub status: ExitStatus,
    pub logs: ProcessLogs,
}

#[derive(Debug, Error)]
pub enum ManagedProcessError {
    #[error("managed process readiness must be configured explicitly")]
    ReadinessNotConfigured,
    #[error("failed to spawn managed program `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("managed process {pid} exited before readiness: {status}")]
    ExitedBeforeReady {
        pid: u32,
        status: ExitStatus,
        logs: ProcessLogs,
    },
    #[error("managed process {pid} readiness timed out after {timeout:?}")]
    ReadinessTimeout {
        pid: u32,
        timeout: Duration,
        termination: TerminationReport,
    },
    #[error("managed process {pid} readiness probe failed: {message}")]
    ReadinessFailed {
        pid: u32,
        message: String,
        termination: TerminationReport,
    },
    #[error("managed process {pid} readiness probe panicked")]
    ReadinessProbePanicked {
        pid: u32,
        termination: TerminationReport,
    },
    #[error("managed process {pid} startup was cancelled")]
    StartupCancelled {
        pid: u32,
        termination: TerminationReport,
    },
    #[error("managed process {pid} graceful shutdown hook failed: {message}")]
    ShutdownHookFailed {
        pid: u32,
        message: String,
        termination: TerminationReport,
    },
    #[error("managed process {pid} graceful shutdown hook panicked")]
    ShutdownHookPanicked {
        pid: u32,
        termination: TerminationReport,
    },
    #[error("managed process group operation `{operation}` failed: {source}")]
    GroupIo {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("managed process reaper task failed: {0}")]
    Reaper(String),
    #[error("managed process {pid} group reap timed out after {timeout:?}")]
    ReapTimeout { pid: u32, timeout: Duration },
    #[error("managed daemon has been stopped")]
    DaemonStopped,
    #[error("managed daemon supervisor failed: {0}")]
    DaemonFailed(String),
}

/// Handle for a process tree created by this module.
///
/// There is intentionally no `from_pid`, `from_child`, or attach API.
pub struct ManagedChild {
    pid: u32,
    state: ManagedChildState,
    child: Option<AsyncGroupChild>,
    stdin: Arc<tokio::sync::Mutex<Option<ChildStdin>>>,
    cancellation: CancellationToken,
    stdout: SharedLog,
    stderr: SharedLog,
    output_tasks: Vec<JoinHandle<()>>,
    output_drain_timeout: Duration,
    reap_timeout: Duration,
    spec_guard: Option<Arc<ManagedProcessSpec>>,
    runtime: tokio::runtime::Handle,
}

impl fmt::Debug for ManagedChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedChild")
            .field("pid", &self.pid)
            .field("state", &self.state)
            .field("logs", &self.logs())
            .finish_non_exhaustive()
    }
}

impl ManagedChild {
    async fn spawn(
        spec: Arc<ManagedProcessSpec>,
        parent_cancellation: &CancellationToken,
    ) -> Result<Self, ManagedProcessError> {
        let readiness = spec
            .readiness
            .clone()
            .ok_or(ManagedProcessError::ReadinessNotConfigured)?;
        let runtime = tokio::runtime::Handle::current();
        spec.register_launch_values();

        let mut command = tokio::process::Command::new(&spec.program);
        command
            .args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if spec.clear_env {
            command.env_clear();
        }
        command.envs(spec.env.iter().map(|(key, value)| (key, value)));
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }

        let mut child = command
            .group()
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| ManagedProcessError::Spawn {
                program: spec
                    .redactor
                    .redact(spec.program.to_string_lossy().as_bytes()),
                source,
            })?;
        let pid = child.id().ok_or_else(|| ManagedProcessError::GroupIo {
            operation: "read spawned process id",
            source: io::Error::other("child exited while spawning"),
        })?;
        let stdin = Arc::new(tokio::sync::Mutex::new(child.inner().stdin.take()));
        let stdout_reader = child.inner().stdout.take();
        let stderr_reader = child.inner().stderr.take();
        let stdout = Arc::new(Mutex::new(BoundedLog::new(
            spec.output.max_bytes_per_stream,
        )));
        let stderr = Arc::new(Mutex::new(BoundedLog::new(
            spec.output.max_bytes_per_stream,
        )));
        let mut output_tasks = Vec::with_capacity(2);
        if let Some(reader) = stdout_reader {
            output_tasks.push(tokio::spawn(capture_output(
                reader,
                spec.redactor.clone(),
                stdout.clone(),
                spec.output.read_chunk_bytes,
            )));
        }
        if let Some(reader) = stderr_reader {
            output_tasks.push(tokio::spawn(capture_output(
                reader,
                spec.redactor.clone(),
                stderr.clone(),
                spec.output.read_chunk_bytes,
            )));
        }

        let cancellation = parent_cancellation.child_token();
        let mut managed = Self {
            pid,
            state: ManagedChildState::Starting,
            child: Some(child),
            stdin,
            cancellation: cancellation.clone(),
            stdout,
            stderr,
            output_tasks,
            output_drain_timeout: spec.output.drain_timeout,
            reap_timeout: spec.reap_timeout,
            spec_guard: Some(spec.clone()),
            runtime,
        };

        let readiness_timeout = spec.readiness_timeout;
        let poll_interval = spec.startup_poll_interval.max(MIN_POLL_INTERVAL);
        let readiness_context = ReadinessContext {
            pid,
            started_at: Instant::now(),
            cancellation: cancellation.clone(),
        };
        let readiness_future =
            match catch_hook_future(|| readiness.wait_until_ready(readiness_context)) {
                Ok(future) => future,
                Err(()) => {
                    let termination = managed.force_terminate().await?;
                    return Err(ManagedProcessError::ReadinessProbePanicked { pid, termination });
                }
            };
        tokio::pin!(readiness_future);
        let deadline = tokio::time::sleep(readiness_timeout);
        tokio::pin!(deadline);
        let mut poll = tokio::time::interval(poll_interval);
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    let termination = managed.force_terminate().await?;
                    return Err(ManagedProcessError::StartupCancelled { pid, termination });
                }
                result = &mut readiness_future => {
                    if let Some(status) = managed.try_wait()? {
                        let report = managed.finish_natural(status, TerminationKind::Exited).await?;
                        return Err(ManagedProcessError::ExitedBeforeReady {
                            pid,
                            status: report.status,
                            logs: report.logs,
                        });
                    }
                    match result {
                        Ok(Ok(())) => {
                            managed.state = ManagedChildState::Ready;
                            return Ok(managed);
                        }
                        Ok(Err(error)) => {
                            let message = spec.redactor.redact(error.to_string());
                            let termination = managed.force_terminate().await?;
                            return Err(ManagedProcessError::ReadinessFailed {
                                pid,
                                message,
                                termination,
                            });
                        }
                        Err(()) => {
                            let termination = managed.force_terminate().await?;
                            return Err(ManagedProcessError::ReadinessProbePanicked {
                                pid,
                                termination,
                            });
                        }
                    }
                }
                _ = poll.tick() => {
                    if let Some(status) = managed.try_wait()? {
                        let report = managed.finish_natural(status, TerminationKind::Exited).await?;
                        return Err(ManagedProcessError::ExitedBeforeReady {
                            pid,
                            status: report.status,
                            logs: report.logs,
                        });
                    }
                }
                _ = &mut deadline => {
                    let termination = managed.force_terminate().await?;
                    return Err(ManagedProcessError::ReadinessTimeout {
                        pid,
                        timeout: readiness_timeout,
                        termination,
                    });
                }
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn state(&self) -> ManagedChildState {
        self.state
    }

    pub fn logs(&self) -> ProcessLogs {
        ProcessLogs {
            stdout: self
                .stdout
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(),
            stderr: self
                .stderr
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(),
        }
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ManagedProcessError> {
        self.child
            .as_mut()
            .expect("managed child handle missing before exit")
            .inner()
            .try_wait()
            .map_err(|source| ManagedProcessError::GroupIo {
                operation: "try_wait for process leader",
                source,
            })
    }

    async fn finish_output(&mut self) {
        let mut tasks = std::mem::take(&mut self.output_tasks);
        if tasks.is_empty() {
            return;
        }
        let drain = async {
            for task in &mut tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(self.output_drain_timeout, drain)
            .await
            .is_err()
        {
            for task in tasks {
                task.abort();
            }
        }
    }

    async fn reap_group(&mut self, force: bool) -> Result<ExitStatus, ManagedProcessError> {
        self.cancellation.cancel();
        self.stdin.lock().await.take();
        let mut child = self
            .child
            .take()
            .expect("managed child reaped more than once");
        if force {
            match child.start_kill() {
                Ok(()) => {}
                Err(error) if process_group_is_already_absent(&error) => {}
                Err(source) => {
                    self.child = Some(child);
                    return Err(ManagedProcessError::GroupIo {
                        operation: "kill process group",
                        source,
                    });
                }
            }
        }
        let guard = self.spec_guard.take();
        // command-group documents that cancelling its Unix wait future can
        // race with a second wait. The dedicated task owns the only wait, and
        // keeps secret files alive until the process group is fully reaped.
        let mut reaper = tokio::spawn(async move {
            let _guard = guard;
            child.wait().await
        });
        let status = tokio::time::timeout(self.reap_timeout, &mut reaper)
            .await
            .map_err(|_| ManagedProcessError::ReapTimeout {
                pid: self.pid,
                timeout: self.reap_timeout,
            })?
            .map_err(|error| ManagedProcessError::Reaper(error.to_string()))?
            .map_err(|source| ManagedProcessError::GroupIo {
                operation: "wait for process group",
                source,
            })?;
        self.state = ManagedChildState::Exited;
        self.finish_output().await;
        Ok(status)
    }

    async fn finish_natural(
        &mut self,
        _observed_status: ExitStatus,
        kind: TerminationKind,
    ) -> Result<TerminationReport, ManagedProcessError> {
        // A daemon leader may exit while helpers remain alive. The inner
        // leader-only `try_wait` above deliberately leaves command-group's
        // group status uncached, allowing this kill + wait to cover the whole
        // POSIX process group or Windows Job Object.
        let status = self.reap_group(true).await?;
        Ok(TerminationReport {
            kind,
            status,
            logs: self.logs(),
        })
    }

    async fn force_terminate(&mut self) -> Result<TerminationReport, ManagedProcessError> {
        self.state = ManagedChildState::Stopping;
        let status = self.reap_group(true).await?;
        Ok(TerminationReport {
            kind: TerminationKind::Forced,
            status,
            logs: self.logs(),
        })
    }

    /// Poll once for an unexpected exit.
    pub async fn poll_exit(&mut self) -> Result<Option<TerminationReport>, ManagedProcessError> {
        let Some(status) = self.try_wait()? else {
            return Ok(None);
        };
        self.finish_natural(status, TerminationKind::Exited)
            .await
            .map(Some)
    }

    /// Wait for natural exit. Cancelling this future synchronously requests a
    /// group kill and schedules a best-effort wait on the captured runtime.
    /// Let this future complete (or use [`ManagedDaemon::close`]) when a
    /// completed reap is required.
    pub async fn wait(mut self) -> Result<TerminationReport, ManagedProcessError> {
        let mut poll = tokio::time::interval(MIN_POLL_INTERVAL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return self.force_terminate().await,
                _ = poll.tick() => {
                    if let Some(status) = self.try_wait()? {
                        return self.finish_natural(status, TerminationKind::Exited).await;
                    }
                }
            }
        }
    }

    /// Request graceful shutdown, wait for the configured deadline, then kill
    /// and reap the complete process group if it is still alive.
    pub async fn shutdown(
        mut self,
        hook: Arc<dyn GracefulShutdown>,
        timeout: Duration,
        redactor: Redactor,
    ) -> Result<TerminationReport, ManagedProcessError> {
        if let Some(status) = self.try_wait()? {
            return self.finish_natural(status, TerminationKind::Exited).await;
        }
        self.state = ManagedChildState::Stopping;
        let deadline_at = Instant::now() + timeout;
        let context = ShutdownContext {
            pid: self.pid,
            stdin: self.stdin.clone(),
            cancellation: self.cancellation.clone(),
        };
        let hook_future = match catch_hook_future(|| hook.shutdown(context)) {
            Ok(future) => future,
            Err(()) => {
                let termination = self.force_terminate().await?;
                return Err(ManagedProcessError::ShutdownHookPanicked {
                    pid: self.pid,
                    termination,
                });
            }
        };
        tokio::pin!(hook_future);
        let deadline = tokio::time::sleep_until(deadline_at);
        tokio::pin!(deadline);
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return self.force_terminate().await,
            _ = &mut deadline => return self.force_terminate().await,
            result = &mut hook_future => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        let message = redactor.redact(error.to_string());
                        let termination = self.force_terminate().await?;
                        return Err(ManagedProcessError::ShutdownHookFailed {
                            pid: self.pid,
                            message,
                            termination,
                        });
                    }
                    Err(()) => {
                        let termination = self.force_terminate().await?;
                        return Err(ManagedProcessError::ShutdownHookPanicked {
                            pid: self.pid,
                            termination,
                        });
                    }
                }
            }
        }

        let mut poll = tokio::time::interval(MIN_POLL_INTERVAL);
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return self.force_terminate().await,
                _ = &mut deadline => return self.force_terminate().await,
                _ = poll.tick() => {
                    if let Some(status) = self.try_wait()? {
                        return self.finish_natural(status, TerminationKind::Graceful).await;
                    }
                }
            }
        }
    }

    fn kill_and_reap_on_drop(&mut self) {
        self.cancellation.cancel();
        for task in self.output_tasks.drain(..) {
            task.abort();
        }
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        let guard = self.spec_guard.take();
        let reaper = async move {
            let _guard = guard;
            let _ = child.wait().await;
        };
        // Tokio currently returns a cancelled JoinHandle after runtime
        // shutdown. Keep Drop panic-free even if that implementation detail
        // changes; group termination was already requested synchronously.
        let _ =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.runtime.spawn(reaper)));
        // Drop is intentionally best-effort: it requests group termination
        // synchronously, but a runtime which is already shutting down cannot
        // promise completion of the scheduled wait. Explicit async lifecycle
        // methods provide the bounded wait contract.
    }
}

fn process_group_is_already_absent(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
    ) {
        return true;
    }

    #[cfg(unix)]
    {
        // command-group uses killpg(2) on Unix. ESRCH means that the leader
        // and every helper in the owned group have already exited, which is
        // the desired idempotent termination result.
        if error.raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
    }

    false
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill_and_reap_on_drop();
    }
}

#[derive(Debug, Clone)]
pub enum ManagedDaemonState {
    Stopped,
    Starting,
    Running { pid: u32, restart_attempt: u32 },
    Backoff { attempt: u32, until: Instant },
    Exited { status: ExitStatus },
    Failed { message: String },
}

#[derive(Debug, Clone)]
pub enum EnsureRunningOutcome {
    Started { pid: u32 },
    Restarted { pid: u32, attempt: u32 },
    AlreadyRunning { pid: u32 },
    Exited(TerminationReport),
}

/// Lifecycle notifications published by a managed daemon.
#[derive(Debug, Clone)]
pub enum ManagedDaemonEvent {
    Ready { pid: u32, restart_attempt: u32 },
    UnexpectedExit(TerminationReport),
    RestartScheduled { attempt: u32, delay: Duration },
    Restarted { pid: u32, attempt: u32 },
    SpawnFailed { attempt: u32, message: String },
    Cancelled(Option<TerminationReport>),
    Stopped(Option<TerminationReport>),
    Failed { message: String },
}

#[derive(Clone)]
struct LiveLogHandles {
    stdout: SharedLog,
    stderr: SharedLog,
}

impl LiveLogHandles {
    fn snapshot(&self) -> ProcessLogs {
        ProcessLogs {
            stdout: self
                .stdout
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(),
            stderr: self
                .stderr
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot(),
        }
    }
}

#[derive(Default)]
struct DaemonShared {
    live_logs: Mutex<Option<LiveLogHandles>>,
    last_logs: Mutex<ProcessLogs>,
    last_exit: Mutex<Option<TerminationReport>>,
    last_error: Mutex<Option<String>>,
}

impl DaemonShared {
    fn set_live_logs(&self, logs: LiveLogHandles) {
        *self.live_logs.lock().unwrap_or_else(|e| e.into_inner()) = Some(logs);
    }

    fn clear_live_logs(&self) {
        self.live_logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    fn record_report(&self, report: &TerminationReport) {
        self.clear_live_logs();
        *self.last_logs.lock().unwrap_or_else(|e| e.into_inner()) = report.logs.clone();
        *self.last_exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(report.clone());
    }

    fn record_error(&self, message: String) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(message);
    }

    fn clear_error(&self) {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    fn logs(&self) -> ProcessLogs {
        if let Some(logs) = self
            .live_logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return logs.snapshot();
        }
        self.last_logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn last_exit(&self) -> Option<TerminationReport> {
        self.last_exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[derive(Debug)]
enum DaemonCommand {
    Stop,
}

#[derive(Debug)]
enum MonitorOutcome {
    Unexpected(TerminationReport),
    Cancelled(TerminationReport),
    Stopped(TerminationReport),
}

/// Background supervisor for one owned daemon.
///
/// Once [`ensure_running`](Self::ensure_running) reports readiness, a dedicated
/// task owns the child, observes unexpected exit, publishes it, and applies
/// the restart policy without requiring another reconcile call.
///
/// [`close`](Self::close) is the explicit lifecycle boundary: it waits for the
/// supervisor's bounded process-group reap. `Drop` only requests cancellation
/// and detaches that task; if the Tokio runtime is already shutting down, Drop
/// cannot promise that asynchronous reaping completed.
pub struct ManagedDaemon {
    spec: Arc<ManagedProcessSpec>,
    state_tx: Option<watch::Sender<ManagedDaemonState>>,
    state_rx: watch::Receiver<ManagedDaemonState>,
    event_tx: broadcast::Sender<ManagedDaemonEvent>,
    command_tx: mpsc::UnboundedSender<DaemonCommand>,
    command_rx: Option<mpsc::UnboundedReceiver<DaemonCommand>>,
    cancellation: CancellationToken,
    supervisor: Option<JoinHandle<Result<Option<TerminationReport>, ManagedProcessError>>>,
    shared: Arc<DaemonShared>,
    stop_requested: bool,
    closed: bool,
}

impl fmt::Debug for ManagedDaemon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedDaemon")
            .field("state", &self.state())
            .field("logs", &self.logs())
            .field("last_error", &self.last_error())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl ManagedDaemon {
    pub fn new(spec: ManagedProcessSpec) -> Self {
        let (state_tx, state_rx) = watch::channel(ManagedDaemonState::Stopped);
        let (event_tx, _) = broadcast::channel(64);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        Self {
            spec: Arc::new(spec),
            state_tx: Some(state_tx),
            state_rx,
            event_tx,
            command_tx,
            command_rx: Some(command_rx),
            cancellation: CancellationToken::new(),
            supervisor: None,
            shared: Arc::new(DaemonShared::default()),
            stop_requested: false,
            closed: false,
        }
    }

    pub fn state(&self) -> ManagedDaemonState {
        self.state_rx.borrow().clone()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<ManagedDaemonState> {
        self.state_rx.clone()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ManagedDaemonEvent> {
        self.event_tx.subscribe()
    }

    pub fn logs(&self) -> ProcessLogs {
        self.shared.logs()
    }

    /// Most recently completed process lifetime, retained across restarts.
    pub fn last_exit(&self) -> Option<TerminationReport> {
        self.shared.last_exit()
    }

    /// Latest unresolved supervisor error. A successful ready transition
    /// clears it.
    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error()
    }

    /// Request immediate cancellation. A running child is force-terminated;
    /// startup and restart backoff are interrupted without another reconcile.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Start the background supervisor and wait for its first ready child.
    pub async fn ensure_running(&mut self) -> Result<EnsureRunningOutcome, ManagedProcessError> {
        if self.closed || self.cancellation.is_cancelled() {
            return Err(ManagedProcessError::DaemonStopped);
        }

        if self.supervisor.is_none() {
            let state_tx = self
                .state_tx
                .take()
                .expect("daemon state sender missing before supervisor start");
            let command_rx = self
                .command_rx
                .take()
                .expect("daemon command receiver missing before supervisor start");
            let (initial_tx, initial_rx) = oneshot::channel();
            let supervisor = tokio::spawn(run_daemon_supervisor(
                self.spec.clone(),
                state_tx,
                self.event_tx.clone(),
                command_rx,
                self.cancellation.clone(),
                self.shared.clone(),
                initial_tx,
            ));
            self.supervisor = Some(supervisor);
            return initial_rx.await.map_err(|_| {
                ManagedProcessError::DaemonFailed(
                    "supervisor ended before publishing initial readiness".into(),
                )
            })?;
        }

        self.current_or_waiting_outcome().await
    }

    /// Compatibility alias. Background monitoring no longer needs polling.
    pub async fn reconcile(&mut self) -> Result<EnsureRunningOutcome, ManagedProcessError> {
        self.ensure_running().await
    }

    async fn current_or_waiting_outcome(
        &mut self,
    ) -> Result<EnsureRunningOutcome, ManagedProcessError> {
        loop {
            match self.state() {
                ManagedDaemonState::Running {
                    pid,
                    restart_attempt: _,
                } => return Ok(EnsureRunningOutcome::AlreadyRunning { pid }),
                ManagedDaemonState::Exited { .. } => {
                    let report = self.shared.last_exit().ok_or_else(|| {
                        ManagedProcessError::DaemonFailed(
                            "exit state published without a termination report".into(),
                        )
                    })?;
                    return Ok(EnsureRunningOutcome::Exited(report));
                }
                ManagedDaemonState::Failed { message } => {
                    return Err(ManagedProcessError::DaemonFailed(message));
                }
                ManagedDaemonState::Stopped if self.supervisor.is_some() => {
                    return Err(ManagedProcessError::DaemonStopped);
                }
                ManagedDaemonState::Stopped
                | ManagedDaemonState::Starting
                | ManagedDaemonState::Backoff { .. } => {}
            }
            self.state_rx.changed().await.map_err(|_| {
                ManagedProcessError::DaemonFailed("supervisor state channel closed".into())
            })?;
            if let ManagedDaemonState::Running {
                pid,
                restart_attempt,
            } = self.state()
            {
                return if restart_attempt == 0 {
                    Ok(EnsureRunningOutcome::Started { pid })
                } else {
                    Ok(EnsureRunningOutcome::Restarted {
                        pid,
                        attempt: restart_attempt,
                    })
                };
            }
        }
    }

    /// Wait for the next observed process termination. Restart policy remains
    /// active in the background.
    pub async fn wait_for_exit(
        &mut self,
    ) -> Result<Option<TerminationReport>, ManagedProcessError> {
        // Subscribe before sampling state so a transition between those two
        // operations is queued rather than missed.
        let mut events = self.subscribe_events();
        match self.state() {
            ManagedDaemonState::Exited { .. } | ManagedDaemonState::Stopped => {
                return Ok(self.shared.last_exit());
            }
            ManagedDaemonState::Failed { message } => {
                return self
                    .shared
                    .last_exit()
                    .map(Some)
                    .ok_or(ManagedProcessError::DaemonFailed(message));
            }
            ManagedDaemonState::Starting
            | ManagedDaemonState::Running { .. }
            | ManagedDaemonState::Backoff { .. } => {}
        }
        loop {
            match events.recv().await {
                Ok(ManagedDaemonEvent::UnexpectedExit(report))
                | Ok(ManagedDaemonEvent::Cancelled(Some(report)))
                | Ok(ManagedDaemonEvent::Stopped(Some(report))) => return Ok(Some(report)),
                Ok(ManagedDaemonEvent::Failed { message }) => {
                    return Err(ManagedProcessError::DaemonFailed(message));
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => match self.state() {
                    ManagedDaemonState::Exited { .. } | ManagedDaemonState::Stopped => {
                        return Ok(self.shared.last_exit());
                    }
                    ManagedDaemonState::Failed { message } => {
                        return self
                            .shared
                            .last_exit()
                            .map(Some)
                            .ok_or(ManagedProcessError::DaemonFailed(message));
                    }
                    ManagedDaemonState::Starting
                    | ManagedDaemonState::Running { .. }
                    | ManagedDaemonState::Backoff { .. } => {}
                },
                Err(broadcast::error::RecvError::Closed) => {
                    return Ok(self.shared.last_exit());
                }
            }
        }
    }

    /// Stop desired state and wait for the background owner to finish its
    /// bounded group reap. Unlike Drop, completion of this future is the
    /// explicit cleanup contract.
    pub async fn close(&mut self) -> Result<Option<TerminationReport>, ManagedProcessError> {
        if self.closed {
            return Ok(self.shared.last_exit());
        }
        let startup_or_backoff = matches!(
            self.state(),
            ManagedDaemonState::Starting | ManagedDaemonState::Backoff { .. }
        );
        let Some(supervisor) = self.supervisor.as_mut() else {
            self.cancellation.cancel();
            if let Some(state_tx) = self.state_tx.as_ref() {
                state_tx.send_replace(ManagedDaemonState::Stopped);
            }
            self.closed = true;
            return Ok(None);
        };

        if !self.stop_requested && !self.cancellation.is_cancelled() {
            self.stop_requested = true;
            if startup_or_backoff {
                self.cancellation.cancel();
            } else {
                let _ = self.command_tx.send(DaemonCommand::Stop);
            }
        }

        let result = supervisor
            .await
            .map_err(|error| ManagedProcessError::Reaper(error.to_string()))?;
        self.supervisor.take();
        self.closed = true;
        result
    }

    pub async fn stop(&mut self) -> Result<Option<TerminationReport>, ManagedProcessError> {
        self.close().await
    }
}

impl Drop for ManagedDaemon {
    fn drop(&mut self) {
        if !self.closed {
            self.cancellation.cancel();
        }
        // Dropping JoinHandle detaches the supervisor. It continues to own the
        // process while the runtime is alive; ManagedChild's own Drop still
        // synchronously requests a group kill during runtime shutdown.
    }
}

impl ManagedChild {
    fn live_log_handles(&self) -> LiveLogHandles {
        LiveLogHandles {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
        }
    }
}

fn publish_state(state_tx: &watch::Sender<ManagedDaemonState>, state: ManagedDaemonState) {
    state_tx.send_replace(state);
}

fn publish_event(event_tx: &broadcast::Sender<ManagedDaemonEvent>, event: ManagedDaemonEvent) {
    let _ = event_tx.send(event);
}

fn report_from_error(error: &ManagedProcessError) -> Option<TerminationReport> {
    match error {
        ManagedProcessError::ReadinessTimeout { termination, .. }
        | ManagedProcessError::ReadinessFailed { termination, .. }
        | ManagedProcessError::ReadinessProbePanicked { termination, .. }
        | ManagedProcessError::StartupCancelled { termination, .. }
        | ManagedProcessError::ShutdownHookFailed { termination, .. }
        | ManagedProcessError::ShutdownHookPanicked { termination, .. } => {
            Some(termination.clone())
        }
        ManagedProcessError::ExitedBeforeReady { status, logs, .. } => Some(TerminationReport {
            kind: TerminationKind::Exited,
            status: *status,
            logs: logs.clone(),
        }),
        _ => None,
    }
}

async fn wait_for_restart(
    until: Instant,
    commands: &mut mpsc::UnboundedReceiver<DaemonCommand>,
    cancellation: &CancellationToken,
) -> bool {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => false,
        command = commands.recv() => {
            match command {
                Some(DaemonCommand::Stop) | None => false,
            }
        }
        _ = tokio::time::sleep_until(until) => true,
    }
}

async fn run_daemon_supervisor(
    spec: Arc<ManagedProcessSpec>,
    state_tx: watch::Sender<ManagedDaemonState>,
    event_tx: broadcast::Sender<ManagedDaemonEvent>,
    mut commands: mpsc::UnboundedReceiver<DaemonCommand>,
    cancellation: CancellationToken,
    shared: Arc<DaemonShared>,
    initial_tx: oneshot::Sender<Result<EnsureRunningOutcome, ManagedProcessError>>,
) -> Result<Option<TerminationReport>, ManagedProcessError> {
    let mut initial_tx = Some(initial_tx);
    let mut restart_attempts = 0_u32;
    let mut last_report = None;

    loop {
        publish_state(&state_tx, ManagedDaemonState::Starting);
        let spawn_result = ManagedChild::spawn(spec.clone(), &cancellation).await;
        let mut child = match spawn_result {
            Ok(child) => child,
            Err(error) => {
                let report = report_from_error(&error);
                if let Some(report) = report.as_ref() {
                    shared.record_report(report);
                    last_report = Some(report.clone());
                } else {
                    shared.clear_live_logs();
                }
                let message = spec.redactor.redact(error.to_string());
                shared.record_error(message.clone());

                if let Some(initial_tx) = initial_tx.take() {
                    let _ = initial_tx.send(Err(error));
                } else {
                    publish_event(
                        &event_tx,
                        ManagedDaemonEvent::SpawnFailed {
                            attempt: restart_attempts,
                            message: message.clone(),
                        },
                    );
                }

                if cancellation.is_cancelled() {
                    publish_state(&state_tx, ManagedDaemonState::Stopped);
                    publish_event(
                        &event_tx,
                        ManagedDaemonEvent::Cancelled(last_report.clone()),
                    );
                    return Ok(last_report);
                }

                if !spec.restart.permits(None, restart_attempts) {
                    publish_state(
                        &state_tx,
                        ManagedDaemonState::Failed {
                            message: message.clone(),
                        },
                    );
                    publish_event(&event_tx, ManagedDaemonEvent::Failed { message });
                    return Ok(last_report);
                }

                restart_attempts = restart_attempts.saturating_add(1);
                let delay = spec.restart.backoff(restart_attempts);
                let until = Instant::now() + delay;
                publish_state(
                    &state_tx,
                    ManagedDaemonState::Backoff {
                        attempt: restart_attempts,
                        until,
                    },
                );
                publish_event(
                    &event_tx,
                    ManagedDaemonEvent::RestartScheduled {
                        attempt: restart_attempts,
                        delay,
                    },
                );
                if !wait_for_restart(until, &mut commands, &cancellation).await {
                    publish_state(&state_tx, ManagedDaemonState::Stopped);
                    let event = if cancellation.is_cancelled() {
                        ManagedDaemonEvent::Cancelled(last_report.clone())
                    } else {
                        ManagedDaemonEvent::Stopped(last_report.clone())
                    };
                    publish_event(&event_tx, event);
                    return Ok(last_report);
                }
                continue;
            }
        };

        let pid = child.pid();
        shared.set_live_logs(child.live_log_handles());
        shared.clear_error();
        publish_state(
            &state_tx,
            ManagedDaemonState::Running {
                pid,
                restart_attempt: restart_attempts,
            },
        );
        publish_event(
            &event_tx,
            ManagedDaemonEvent::Ready {
                pid,
                restart_attempt: restart_attempts,
            },
        );
        if restart_attempts != 0 {
            publish_event(
                &event_tx,
                ManagedDaemonEvent::Restarted {
                    pid,
                    attempt: restart_attempts,
                },
            );
        }
        if let Some(initial_tx) = initial_tx.take() {
            let outcome = if restart_attempts == 0 {
                EnsureRunningOutcome::Started { pid }
            } else {
                EnsureRunningOutcome::Restarted {
                    pid,
                    attempt: restart_attempts,
                }
            };
            let _ = initial_tx.send(Ok(outcome));
        }

        let mut poll = tokio::time::interval(spec.monitor_poll_interval.max(MIN_POLL_INTERVAL));
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let monitor = loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    break child.force_terminate().await.map(MonitorOutcome::Cancelled);
                }
                command = commands.recv() => {
                    match command {
                        Some(DaemonCommand::Stop) | None => {
                            break child
                                .shutdown(
                                    spec.stop.clone(),
                                    spec.shutdown_timeout,
                                    spec.redactor.clone(),
                                )
                                .await
                                .map(MonitorOutcome::Stopped);
                        }
                    }
                }
                _ = poll.tick() => {
                    match child.poll_exit().await {
                        Ok(Some(report)) => break Ok(MonitorOutcome::Unexpected(report)),
                        Ok(None) => {}
                        Err(error) => break Err(error),
                    }
                }
            }
        };

        let outcome = match monitor {
            Ok(outcome) => outcome,
            Err(error) => {
                shared.clear_live_logs();
                let message = spec.redactor.redact(error.to_string());
                shared.record_error(message.clone());
                publish_state(
                    &state_tx,
                    ManagedDaemonState::Failed {
                        message: message.clone(),
                    },
                );
                publish_event(
                    &event_tx,
                    ManagedDaemonEvent::Failed {
                        message: message.clone(),
                    },
                );
                return Err(error);
            }
        };

        match outcome {
            MonitorOutcome::Cancelled(report) => {
                shared.record_report(&report);
                publish_state(&state_tx, ManagedDaemonState::Stopped);
                publish_event(
                    &event_tx,
                    ManagedDaemonEvent::Cancelled(Some(report.clone())),
                );
                return Ok(Some(report));
            }
            MonitorOutcome::Stopped(report) => {
                shared.record_report(&report);
                publish_state(&state_tx, ManagedDaemonState::Stopped);
                publish_event(&event_tx, ManagedDaemonEvent::Stopped(Some(report.clone())));
                return Ok(Some(report));
            }
            MonitorOutcome::Unexpected(report) => {
                let status = report.status;
                shared.record_report(&report);
                last_report = Some(report.clone());
                publish_state(&state_tx, ManagedDaemonState::Exited { status });
                publish_event(&event_tx, ManagedDaemonEvent::UnexpectedExit(report));

                if !spec.restart.permits(Some(status), restart_attempts) {
                    return Ok(last_report);
                }
                restart_attempts = restart_attempts.saturating_add(1);
                let delay = spec.restart.backoff(restart_attempts);
                let until = Instant::now() + delay;
                publish_state(
                    &state_tx,
                    ManagedDaemonState::Backoff {
                        attempt: restart_attempts,
                        until,
                    },
                );
                publish_event(
                    &event_tx,
                    ManagedDaemonEvent::RestartScheduled {
                        attempt: restart_attempts,
                        delay,
                    },
                );
                if !wait_for_restart(until, &mut commands, &cancellation).await {
                    publish_state(&state_tx, ManagedDaemonState::Stopped);
                    let event = if cancellation.is_cancelled() {
                        ManagedDaemonEvent::Cancelled(last_report.clone())
                    } else {
                        ManagedDaemonEvent::Stopped(last_report.clone())
                    };
                    publish_event(&event_tx, event);
                    return Ok(last_report);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
        io::{BufRead, Write},
        net::{SocketAddr, TcpStream},
        process::Command,
        sync::mpsc as std_mpsc,
        thread,
        time::{Duration as StdDuration, Instant as StdInstant},
    };
    use tokio::net::TcpListener;

    const HELPER_MODE: &str = "WUTHER_PROCESS_HELPER_MODE";
    const READY_ADDR: &str = "WUTHER_PROCESS_HELPER_READY_ADDR";
    const TRIGGER_FILE: &str = "WUTHER_PROCESS_HELPER_TRIGGER_FILE";
    const RELEASE_FILE: &str = "WUTHER_PROCESS_HELPER_RELEASE_FILE";
    const ENV_SECRET: &str = "WUTHER_PROCESS_HELPER_ENV_SECRET";
    const DESC_READY_FILE: &str = "WUTHER_PROCESS_HELPER_DESC_READY_FILE";
    const DESC_TRIGGER_FILE: &str = "WUTHER_PROCESS_HELPER_DESC_TRIGGER_FILE";
    const LEAK_FILE: &str = "WUTHER_PROCESS_HELPER_LEAK_FILE";
    const HOOK_PANIC_PAYLOAD: &str = "unregistered-hook-panic-payload-must-stay-private";

    fn helper_args() -> [&'static str; 4] {
        [
            "--exact",
            "process::tests::managed_process_test_helper",
            "--nocapture",
            "--test-threads=1",
        ]
    }

    fn env_path(key: &str) -> PathBuf {
        PathBuf::from(env::var_os(key).unwrap_or_else(|| panic!("{key} is required")))
    }

    fn wait_for_path(path: &Path) {
        while !path.exists() {
            thread::sleep(StdDuration::from_millis(1));
        }
    }

    fn send_ready() {
        let address = env::var(READY_ADDR)
            .expect("ready address")
            .parse::<SocketAddr>()
            .expect("valid ready address");
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            match TcpStream::connect_timeout(&address, StdDuration::from_millis(100)) {
                Ok(mut stream) => {
                    stream.write_all(b"READY\n").expect("write ready handshake");
                    return;
                }
                Err(error) if StdInstant::now() < deadline => {
                    let _ = error;
                    thread::sleep(StdDuration::from_millis(1));
                }
                Err(error) => panic!("ready handshake failed: {error}"),
            }
        }
    }

    fn run_control_helper() {
        send_ready();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("read shutdown command");
        assert_eq!(line, "stop\n");
    }

    fn run_control_or_trigger_helper() {
        send_ready();
        let trigger = env_path(TRIGGER_FILE);
        let (line_tx, line_rx) = std_mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            let _ = line_tx.send(line);
        });
        loop {
            if trigger.exists() {
                let _ = fs::remove_file(&trigger);
                std::process::exit(9);
            }
            match line_rx.try_recv() {
                Ok(line) => {
                    assert_eq!(line, "stop\n");
                    return;
                }
                Err(std_mpsc::TryRecvError::Empty) => {
                    thread::sleep(StdDuration::from_millis(1));
                }
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    panic!("stdin reader disconnected")
                }
            }
        }
    }

    fn run_output_helper() {
        send_ready();
        let argv_value = env::args()
            .find(|arg| arg == "--nocapture")
            .expect("test harness argv");
        let env_secret = env::var(ENV_SECRET).expect("environment secret");
        print!("{argv_value}|{env_secret}|registered-secret|");
        print!("{}", "x".repeat(512));
        print!("|registered-secret");
        eprint!("{env_secret}");
        std::io::stdout().flush().expect("flush stdout");
        std::io::stderr().flush().expect("flush stderr");
        wait_for_path(&env_path(RELEASE_FILE));
    }

    fn run_leader_with_descendant_helper() {
        let executable = env::current_exe().expect("current test executable");
        let descendant_ready = env_path(DESC_READY_FILE);
        let descendant_trigger = env_path(DESC_TRIGGER_FILE);
        let leak = env_path(LEAK_FILE);
        let mut command = Command::new(executable);
        command
            .args(helper_args())
            .env(HELPER_MODE, "descendant")
            .env(DESC_READY_FILE, &descendant_ready)
            .env(DESC_TRIGGER_FILE, &descendant_trigger)
            .env(LEAK_FILE, &leak)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _descendant = command.spawn().expect("spawn descendant helper");
        wait_for_path(&descendant_ready);
        send_ready();
        wait_for_path(&env_path(TRIGGER_FILE));
        std::process::exit(9);
    }

    fn run_descendant_helper() {
        fs::write(env_path(DESC_READY_FILE), b"ready").expect("publish descendant readiness");
        wait_for_path(&env_path(DESC_TRIGGER_FILE));
        fs::write(env_path(LEAK_FILE), b"leaked").expect("write leak marker");
    }

    /// The same Rust test executable is the child fixture. This avoids shell
    /// startup timing and exercises readiness through a real TCP handshake.
    #[test]
    fn managed_process_test_helper() {
        let Ok(mode) = env::var(HELPER_MODE) else {
            return;
        };
        match mode.as_str() {
            "control" => run_control_helper(),
            "control_or_trigger" => run_control_or_trigger_helper(),
            "early_exit" => std::process::exit(7),
            "no_ready" => loop {
                thread::park_timeout(StdDuration::from_secs(1));
            },
            "output" => run_output_helper(),
            "leader_with_descendant" => run_leader_with_descendant_helper(),
            "descendant" => run_descendant_helper(),
            other => panic!("unknown helper mode: {other}"),
        }
    }

    #[derive(Debug)]
    struct TcpHandshakeProbe {
        listener: Arc<TcpListener>,
    }

    #[async_trait]
    impl ReadinessProbe for TcpHandshakeProbe {
        async fn wait_until_ready(
            &self,
            context: ReadinessContext,
        ) -> Result<(), ProcessHookError> {
            let (mut stream, _) = tokio::select! {
                _ = context.cancellation().cancelled() => {
                    return Err(ProcessHookError::new("readiness cancelled"));
                }
                accepted = self.listener.accept() => {
                    accepted.map_err(|error| ProcessHookError::new(error.to_string()))?
                }
            };
            let mut handshake = [0_u8; 6];
            tokio::select! {
                _ = context.cancellation().cancelled() => {
                    return Err(ProcessHookError::new("readiness cancelled"));
                }
                result = stream.read_exact(&mut handshake) => {
                    result.map_err(|error| ProcessHookError::new(error.to_string()))?;
                }
            }
            if &handshake != b"READY\n" {
                return Err(ProcessHookError::new("invalid readiness handshake"));
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct PanickingReadinessProbe;

    #[async_trait]
    impl ReadinessProbe for PanickingReadinessProbe {
        async fn wait_until_ready(
            &self,
            _context: ReadinessContext,
        ) -> Result<(), ProcessHookError> {
            panic!("{HOOK_PANIC_PAYLOAD}");
        }
    }

    #[derive(Debug)]
    struct PanickingShutdownHook;

    #[async_trait]
    impl GracefulShutdown for PanickingShutdownHook {
        async fn shutdown(&self, _context: ShutdownContext) -> Result<(), ProcessHookError> {
            panic!("{HOOK_PANIC_PAYLOAD}");
        }
    }

    async fn helper_spec(mode: &str) -> ManagedProcessSpec {
        let listener = Arc::new(
            TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("bind readiness listener"),
        );
        let address = listener.local_addr().expect("readiness address");
        let mut spec =
            ManagedProcessSpec::new(env::current_exe().expect("current test executable"));
        spec.args(helper_args());
        spec.env(HELPER_MODE, mode);
        spec.env(READY_ADDR, address.to_string());
        #[cfg(windows)]
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = env::var_os(key) {
                spec.env(key, value);
            }
        }
        spec.with_readiness(Arc::new(TcpHandshakeProbe { listener }));
        spec.readiness_timeout = Duration::from_secs(2);
        spec.startup_poll_interval = Duration::from_millis(2);
        spec.monitor_poll_interval = Duration::from_millis(2);
        spec.shutdown_timeout = Duration::from_millis(300);
        spec.reap_timeout = Duration::from_secs(2);
        spec.output.drain_timeout = Duration::from_millis(300);
        spec
    }

    async fn receive_matching(
        events: &mut broadcast::Receiver<ManagedDaemonEvent>,
        predicate: impl Fn(&ManagedDaemonEvent) -> bool,
    ) -> ManagedDaemonEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Ok(event) if predicate(&event) => return event,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("daemon event channel closed")
                    }
                }
            }
        })
        .await
        .expect("matching daemon event")
    }

    #[tokio::test]
    async fn readiness_requires_explicit_opt_in() {
        let mut spec =
            ManagedProcessSpec::new(env::current_exe().expect("current test executable"));
        spec.args(helper_args());
        spec.env(HELPER_MODE, "early_exit");
        let mut daemon = ManagedDaemon::new(spec);

        let error = daemon.ensure_running().await.unwrap_err();
        assert!(matches!(error, ManagedProcessError::ReadinessNotConfigured));
        daemon.close().await.unwrap();
    }

    #[tokio::test]
    async fn starts_after_real_handshake_and_closes_gracefully() {
        let mut spec = helper_spec("control").await;
        spec.stop = Arc::new(StdinGracefulShutdown::new(b"stop\n"));
        let mut daemon = ManagedDaemon::new(spec);

        assert!(matches!(
            daemon.ensure_running().await.unwrap(),
            EnsureRunningOutcome::Started { .. }
        ));
        assert!(matches!(
            daemon.state(),
            ManagedDaemonState::Running {
                restart_attempt: 0,
                ..
            }
        ));
        let report = daemon.close().await.unwrap().unwrap();
        assert_eq!(report.kind, TerminationKind::Graceful);
        assert!(report.status.success());
    }

    #[tokio::test]
    async fn detects_exit_before_readiness() {
        let spec = helper_spec("early_exit").await;
        let mut daemon = ManagedDaemon::new(spec);

        let error = daemon.ensure_running().await.unwrap_err();
        match error {
            ManagedProcessError::ExitedBeforeReady { status, .. } => {
                assert_eq!(status.code(), Some(7));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        daemon.close().await.unwrap();
    }

    #[tokio::test]
    async fn readiness_timeout_force_kills_and_reaps_group() {
        let mut spec = helper_spec("no_ready").await;
        spec.readiness_timeout = Duration::from_millis(50);
        let mut daemon = ManagedDaemon::new(spec);

        let error = daemon.ensure_running().await.unwrap_err();
        match error {
            ManagedProcessError::ReadinessTimeout { termination, .. } => {
                assert_eq!(termination.kind, TerminationKind::Forced);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        daemon.close().await.unwrap();
    }

    #[tokio::test]
    async fn readiness_panic_is_fixed_public_error_and_reaps_group() {
        let mut spec = helper_spec("no_ready").await;
        spec.with_readiness(Arc::new(PanickingReadinessProbe));
        let mut daemon = ManagedDaemon::new(spec);

        let error = daemon.ensure_running().await.unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        let termination = match &error {
            ManagedProcessError::ReadinessProbePanicked { termination, .. } => termination,
            other => panic!("unexpected error: {other:?}"),
        };
        assert_eq!(termination.kind, TerminationKind::Forced);
        assert!(rendered.contains("readiness probe panicked"));
        assert!(!rendered.contains(HOOK_PANIC_PAYLOAD));
        assert!(
            !format!("{:?}", termination.logs).contains(HOOK_PANIC_PAYLOAD),
            "panic payload escaped into managed child logs"
        );
        assert!(
            !daemon
                .last_error()
                .expect("readiness error is retained")
                .contains(HOOK_PANIC_PAYLOAD)
        );

        let report = daemon
            .close()
            .await
            .unwrap()
            .expect("forced termination report");
        assert_eq!(report.kind, TerminationKind::Forced);
        assert!(!format!("{:?}", daemon.state()).contains(HOOK_PANIC_PAYLOAD));
    }

    #[tokio::test]
    async fn shutdown_timeout_force_kills_and_reaps_group() {
        let mut spec = helper_spec("control").await;
        spec.stop = Arc::new(NoopGracefulShutdown);
        spec.shutdown_timeout = Duration::from_millis(50);
        let mut daemon = ManagedDaemon::new(spec);
        daemon.ensure_running().await.unwrap();

        let report = daemon.close().await.unwrap().unwrap();
        assert_eq!(report.kind, TerminationKind::Forced);
        assert!(!report.status.success());
    }

    #[tokio::test]
    async fn shutdown_hook_panic_is_fixed_public_error_and_reaps_group() {
        let mut spec = helper_spec("control").await;
        spec.stop = Arc::new(PanickingShutdownHook);
        let mut daemon = ManagedDaemon::new(spec);
        daemon.ensure_running().await.unwrap();

        let error = daemon.close().await.unwrap_err();
        let rendered = format!("{error}\n{error:?}");
        let termination = match &error {
            ManagedProcessError::ShutdownHookPanicked { termination, .. } => termination,
            other => panic!("unexpected error: {other:?}"),
        };
        assert_eq!(termination.kind, TerminationKind::Forced);
        assert!(rendered.contains("graceful shutdown hook panicked"));
        assert!(!rendered.contains(HOOK_PANIC_PAYLOAD));
        assert!(
            !format!("{:?}", termination.logs).contains(HOOK_PANIC_PAYLOAD),
            "panic payload escaped into managed child logs"
        );
        assert!(
            !daemon
                .last_error()
                .expect("shutdown error is retained")
                .contains(HOOK_PANIC_PAYLOAD)
        );
        assert!(!format!("{:?}", daemon.state()).contains(HOOK_PANIC_PAYLOAD));
    }

    #[tokio::test]
    async fn output_is_bounded_and_sensitive_sources_are_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let release = directory.path().join("release");
        let mut spec = helper_spec("output").await;
        spec.env(ENV_SECRET, "env-secret");
        spec.env(RELEASE_FILE, release.as_os_str());
        spec.register_secret("registered-secret");
        spec.output = OutputPolicy {
            max_bytes_per_stream: 96,
            read_chunk_bytes: 3,
            drain_timeout: Duration::from_millis(300),
        };
        let mut daemon = ManagedDaemon::new(spec);
        daemon.ensure_running().await.unwrap();

        fs::write(&release, b"go").unwrap();
        let report = daemon.wait_for_exit().await.unwrap().unwrap();
        let combined = format!("{}{}", report.logs.stdout.text, report.logs.stderr.text);
        assert!(!combined.contains("--nocapture"));
        assert!(!combined.contains("env-secret"));
        assert!(!combined.contains("registered-secret"));
        assert!(combined.contains("[REDACTED]"));
        assert!(report.logs.stdout.truncated);
        assert!(report.logs.stdout.text.len() <= 96);
        assert!(report.logs.stderr.text.len() <= 96);
        daemon.close().await.unwrap();
    }

    #[tokio::test]
    async fn unexpected_exit_is_published_and_restarted_without_reconcile() {
        let directory = tempfile::tempdir().unwrap();
        let trigger = directory.path().join("exit");
        let mut spec = helper_spec("control_or_trigger").await;
        spec.env(TRIGGER_FILE, trigger.as_os_str());
        spec.stop = Arc::new(StdinGracefulShutdown::new(b"stop\n"));
        spec.restart = RestartPolicy {
            condition: RestartCondition::OnFailure,
            max_restarts: 1,
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(5),
        };
        let mut daemon = ManagedDaemon::new(spec);
        let mut events = daemon.subscribe_events();
        daemon.ensure_running().await.unwrap();

        fs::write(&trigger, b"exit").unwrap();
        let exit = receive_matching(&mut events, |event| {
            matches!(event, ManagedDaemonEvent::UnexpectedExit(_))
        })
        .await;
        let ManagedDaemonEvent::UnexpectedExit(report) = exit else {
            unreachable!()
        };
        assert_eq!(report.status.code(), Some(9));
        let restarted = receive_matching(&mut events, |event| {
            matches!(event, ManagedDaemonEvent::Restarted { attempt: 1, .. })
        })
        .await;
        assert!(matches!(
            restarted,
            ManagedDaemonEvent::Restarted { attempt: 1, .. }
        ));
        assert!(matches!(
            daemon.state(),
            ManagedDaemonState::Running {
                restart_attempt: 1,
                ..
            }
        ));
        assert_eq!(
            daemon
                .last_exit()
                .expect("restart retains operational exit history")
                .status
                .code(),
            Some(9)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), daemon.wait_for_exit())
                .await
                .is_err(),
            "a restarted child must not replay the previous exit as its next exit"
        );

        let report = daemon.close().await.unwrap().unwrap();
        assert_eq!(report.kind, TerminationKind::Graceful);
    }

    #[tokio::test]
    async fn cancellation_force_terminates_running_child() {
        let spec = helper_spec("control").await;
        let mut daemon = ManagedDaemon::new(spec);
        daemon.ensure_running().await.unwrap();

        daemon.cancel();
        let report = tokio::time::timeout(Duration::from_secs(1), daemon.close())
            .await
            .expect("cancelled daemon closes")
            .unwrap()
            .unwrap();
        assert_eq!(report.kind, TerminationKind::Forced);
        assert!(matches!(daemon.state(), ManagedDaemonState::Stopped));
    }

    #[tokio::test]
    async fn cancellation_interrupts_restart_backoff() {
        let directory = tempfile::tempdir().unwrap();
        let trigger = directory.path().join("exit");
        let mut spec = helper_spec("control_or_trigger").await;
        spec.env(TRIGGER_FILE, trigger.as_os_str());
        spec.restart = RestartPolicy {
            condition: RestartCondition::OnFailure,
            max_restarts: 1,
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(5),
        };
        let mut daemon = ManagedDaemon::new(spec);
        let mut events = daemon.subscribe_events();
        daemon.ensure_running().await.unwrap();

        fs::write(&trigger, b"exit").unwrap();
        receive_matching(&mut events, |event| {
            matches!(
                event,
                ManagedDaemonEvent::RestartScheduled { attempt: 1, .. }
            )
        })
        .await;
        daemon.cancel();
        tokio::time::timeout(Duration::from_millis(500), daemon.close())
            .await
            .expect("backoff cancellation is immediate")
            .unwrap();
        assert!(matches!(daemon.state(), ManagedDaemonState::Stopped));
    }

    #[tokio::test]
    async fn leader_exit_terminates_and_reaps_remaining_group() {
        let directory = tempfile::tempdir().unwrap();
        let leader_trigger = directory.path().join("leader-exit");
        let descendant_ready = directory.path().join("descendant-ready");
        let descendant_trigger = directory.path().join("descendant-trigger");
        let leak = directory.path().join("descendant-leaked");
        let mut spec = helper_spec("leader_with_descendant").await;
        spec.env(TRIGGER_FILE, leader_trigger.as_os_str());
        spec.env(DESC_READY_FILE, descendant_ready.as_os_str());
        spec.env(DESC_TRIGGER_FILE, descendant_trigger.as_os_str());
        spec.env(LEAK_FILE, leak.as_os_str());
        let mut daemon = ManagedDaemon::new(spec);
        let mut events = daemon.subscribe_events();
        daemon.ensure_running().await.unwrap();

        fs::write(&leader_trigger, b"exit").unwrap();
        receive_matching(&mut events, |event| {
            matches!(event, ManagedDaemonEvent::UnexpectedExit(_))
        })
        .await;
        fs::write(&descendant_trigger, b"leak").unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !leak.exists(),
            "leader exit left a process-group descendant alive"
        );
        daemon.close().await.unwrap();
    }

    #[test]
    fn streaming_redactor_covers_chunk_boundaries() {
        let redactor = Redactor::new();
        redactor.register("split-secret");
        let mut stream = StreamingRedactor::new(redactor);
        assert_eq!(stream.push(b"before split-", false), b"before ");
        assert_eq!(stream.push(b"secret after", true), b"[REDACTED] after");
    }

    #[test]
    fn captured_runtime_spawn_is_non_panicking_after_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(handle.spawn(async {}));
        }));
        assert!(result.is_ok());
    }

    #[test]
    fn secret_file_drop_removes_path() {
        let redactor = Redactor::new();
        let path = {
            let file = SecretFile::create(b"top-secret", &redactor).unwrap();
            let path = file.path().to_path_buf();
            assert!(path.exists());
            assert_eq!(redactor.redact("top-secret"), "[REDACTED]");
            path
        };
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let redactor = Redactor::new();
        let file = SecretFile::create(b"top-secret", &redactor).unwrap();
        let mode = fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn an_absent_unix_process_group_is_an_idempotent_kill_result() {
        let error = io::Error::from_raw_os_error(libc::ESRCH);
        assert!(process_group_is_already_absent(&error));
    }
}
