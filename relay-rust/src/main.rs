mod config;
mod protocol;
mod ratelimit;
mod server;

use std::env;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use config::{load_config, LogFormat};
use tracing::error;

fn main() {
    let config_path = parse_config_path(env::args().skip(1));
    let cfg = match load_config(config_path.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("load config: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = init_tracing(&cfg.log_level, cfg.log_format) {
        eprintln!("build logger: {err}");
        process::exit(1);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&shutdown);
    if let Err(err) = ctrlc::set_handler(move || {
        signal_flag.store(true, Ordering::SeqCst);
    }) {
        error!(error = %err, "install signal handler failed");
        process::exit(1);
    }

    let server = match server::Server::new(cfg) {
        Ok(server) => server,
        Err(err) => {
            error!(error = %err, "create relay server");
            process::exit(1);
        }
    };

    if let Err(err) = server.run(shutdown) {
        error!(error = %err, "relay exited");
        process::exit(1);
    }
}

fn parse_config_path<I>(mut args: I) -> Option<String>
where
    I: Iterator<Item = String>,
{
    while let Some(arg) = args.next() {
        if arg == "-config" || arg == "--config" {
            return args.next();
        }
    }
    None
}

fn init_tracing(level: &str, format: LogFormat) -> Result<(), String> {
    let level = match level.to_ascii_lowercase().as_str() {
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        other => return Err(format!("unsupported log level {other:?}")),
    };

    let builder = tracing_subscriber::fmt().with_max_level(level);
    match format {
        LogFormat::Json => builder.json().with_target(false).init(),
        LogFormat::Text => builder.with_target(false).init(),
    }
    Ok(())
}
