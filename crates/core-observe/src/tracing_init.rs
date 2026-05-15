use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::Context, prelude::*};

use crate::log_bus::LogBus;

static LOG_BUS: Lazy<RwLock<Option<Arc<LogBus>>>> = Lazy::new(|| RwLock::new(None));
static LOG_FILE_GUARD: Lazy<RwLock<Option<WorkerGuard>>> = Lazy::new(|| RwLock::new(None));

const DEFAULT_RP_LOG: &str = concat!(
    "info,",
    "capture::tun=debug,",
    "capture::traffic=debug,",
    "capture::dispatch=debug,",
    "capture::accept=debug,",
    "capture::udp=debug,",
    "capture::dns=debug,",
    "capture::stack=debug,",
    "capture::linux::tun=debug,",
    "capture::linux::cmd=debug,",
    "capture::tproxy=debug"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracingFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingFileConfig {
    pub enabled: bool,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingConfig {
    pub enabled: bool,
    pub level: String,
    pub filter: Option<String>,
    pub stdout: bool,
    pub file: Option<TracingFileConfig>,
    pub format: TracingFormat,
}

impl TracingConfig {
    fn from_env_defaults() -> Self {
        let filter = std::env::var("RP_LOG").unwrap_or_else(|_| DEFAULT_RP_LOG.into());
        let format = std::env::var("RP_LOG_FORMAT")
            .map(|s| {
                if s.eq_ignore_ascii_case("json") {
                    TracingFormat::Json
                } else {
                    TracingFormat::Text
                }
            })
            .unwrap_or(TracingFormat::Text);
        Self {
            enabled: true,
            level: "info".into(),
            filter: Some(filter),
            stdout: true,
            file: None,
            format,
        }
    }
}

/// 简单初始化：环境变量 `RP_LOG`、默认 info + capture 关键调试目标；`RP_LOG_FORMAT=json` 启用 JSON。
pub fn init_tracing() {
    init_tracing_with_config(TracingConfig::from_env_defaults(), None);
}

/// 同上，但同时把所有 tracing 事件桥接到 [`LogBus`]，供 Clash `/logs` WS 流式输出。
pub fn init_tracing_with_bus(bus: Option<Arc<LogBus>>) {
    init_tracing_with_config(TracingConfig::from_env_defaults(), bus);
}

pub fn init_tracing_with_config(config: TracingConfig, bus: Option<Arc<LogBus>>) {
    if let Some(bus) = bus {
        set_log_bus(bus);
    }

    if !config.enabled || config.level.eq_ignore_ascii_case("off") {
        return;
    }

    let filter_directive = configured_filter_directive(&config);
    let fallback_directive = config.level.trim().to_ascii_lowercase();
    let filter = EnvFilter::try_new(&filter_directive).unwrap_or_else(|e| {
        eprintln!(
            "invalid log filter `{filter_directive}`: {e}; fallback to level `{fallback_directive}`"
        );
        EnvFilter::try_new(&fallback_directive).unwrap_or_else(|_| EnvFilter::new(DEFAULT_RP_LOG))
    });
    let file_writer = prepare_file_writer(config.file.as_ref());

    match config.format {
        TracingFormat::Json => {
            let stdout_layer = config.stdout.then(|| fmt::layer().json());
            let file_layer = file_writer.map(|writer| fmt::layer().json().with_writer(writer));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .with(BusLayer)
                .try_init();
        }
        TracingFormat::Text => {
            let stdout_layer = config
                .stdout
                .then(|| fmt::layer().with_target(true).with_level(true));
            let file_layer = file_writer.map(|writer| {
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_writer(writer)
            });
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .with(BusLayer)
                .try_init();
        }
    }
}

pub fn attach_log_bus(bus: Arc<LogBus>) {
    set_log_bus(bus);
}

fn set_log_bus(bus: Arc<LogBus>) {
    *LOG_BUS.write() = Some(bus);
}

fn configured_filter_directive(config: &TracingConfig) -> String {
    if let Some(filter) = config
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        filter.to_string()
    } else {
        config.level.trim().to_ascii_lowercase()
    }
}

fn prepare_file_writer(
    file: Option<&TracingFileConfig>,
) -> Option<tracing_appender::non_blocking::NonBlocking> {
    let file = file.filter(|f| f.enabled)?;
    let log_file = match open_log_file(&file.path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("failed to open log file {}: {e}", file.path.display());
            return None;
        }
    };
    let (writer, guard) = tracing_appender::non_blocking(log_file);
    *LOG_FILE_GUARD.write() = Some(guard);
    Some(writer)
}

fn open_log_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// tracing → LogBus 桥层。把每条事件按 level 分类塞 `LogEvent { type, payload }`。
pub struct BusLayer;

impl<S: Subscriber> Layer<S> for BusLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(bus) = LOG_BUS.read().clone() else {
            return;
        };
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warning",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "debug",
        };
        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);
        let payload = if visitor.message.is_empty() {
            visitor.fields
        } else if visitor.fields.is_empty() {
            visitor.message
        } else {
            format!("{} {}", visitor.message, visitor.fields)
        };
        bus.push(level, payload);
    }
}

#[derive(Default)]
struct StringVisitor {
    message: String,
    fields: String,
}

impl Visit for StringVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields
                .push_str(&format!("{}={:?}", field.name(), value));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields.push_str(&format!("{}={}", field.name(), value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_layer_accepts_log_bus_after_layer_exists() {
        *LOG_BUS.write() = None;

        let bus = Arc::new(LogBus::new(16));
        let mut rx = bus.subscribe();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("trace"))
            .with(BusLayer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "observe::test", "before bus");
            assert!(rx.try_recv().is_err());

            set_log_bus(bus);
            tracing::info!(target: "observe::test", answer = 42, "after bus");
        });

        let ev = rx.try_recv().expect("event after attaching bus");
        assert_eq!(ev.level, "info");
        assert!(ev.payload.contains("after bus"));
        assert!(ev.payload.contains("answer=42"));

        *LOG_BUS.write() = None;
    }

    #[test]
    fn default_filter_keeps_tun_debug_logs_visible() {
        let filter = EnvFilter::try_new(DEFAULT_RP_LOG).expect("default filter must parse");
        let _ = filter;
        assert!(DEFAULT_RP_LOG.contains("capture::tun=debug"));
        assert!(DEFAULT_RP_LOG.contains("capture::traffic=debug"));
        assert!(DEFAULT_RP_LOG.contains("capture::linux::cmd=debug"));
    }

    #[test]
    fn configured_filter_prefers_user_filter_over_level() {
        let cfg = TracingConfig {
            enabled: true,
            level: "warn".into(),
            filter: Some("info,capture::traffic=trace".into()),
            stdout: true,
            file: None,
            format: TracingFormat::Text,
        };

        assert_eq!(
            configured_filter_directive(&cfg),
            "info,capture::traffic=trace"
        );
    }

    #[test]
    fn configured_filter_uses_plain_level_when_no_filter_is_set() {
        let cfg = TracingConfig {
            enabled: true,
            level: "error".into(),
            filter: None,
            stdout: true,
            file: None,
            format: TracingFormat::Text,
        };

        assert_eq!(configured_filter_directive(&cfg), "error");
    }

    #[test]
    fn configured_log_file_creates_parent_directory() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-log-test-{}/nested/kernel.log",
            uuid::Uuid::new_v4()
        ));
        assert!(!path.exists());

        let file = open_log_file(&path).expect("log file should open");
        drop(file);

        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent().and_then(|p| p.parent()) {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}
