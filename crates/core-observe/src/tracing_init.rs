use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

use crate::log_bus::LogBus;

/// 简单初始化：环境变量 `RP_LOG`、默认 info；`RP_LOG_FORMAT=json` 启用 JSON。
pub fn init_tracing() {
    init_tracing_with_bus(None);
}

/// 同上，但同时把所有 tracing 事件桥接到 [`LogBus`]，供 Clash `/logs` WS 流式输出。
pub fn init_tracing_with_bus(bus: Option<Arc<LogBus>>) {
    let env = std::env::var("RP_LOG").unwrap_or_else(|_| "info".into());
    let filter = EnvFilter::try_new(&env).unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("RP_LOG_FORMAT").map(|s| s == "json").unwrap_or(false);

    let registry = tracing_subscriber::registry().with(filter);
    let bus_layer = bus.map(|b| BusLayer { bus: b });
    if json {
        let layer = fmt::layer().json();
        let _ = registry.with(layer).with(bus_layer).try_init();
    } else {
        let layer = fmt::layer().with_target(true).with_level(true);
        let _ = registry.with(layer).with(bus_layer).try_init();
    }
}

/// tracing → LogBus 桥层。把每条事件按 level 分类塞 `LogEvent { type, payload }`。
pub struct BusLayer {
    bus: Arc<LogBus>,
}

impl<S: Subscriber> Layer<S> for BusLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
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
        self.bus.push(level, payload);
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
            self.fields.push_str(&format!("{}={:?}", field.name(), value));
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
