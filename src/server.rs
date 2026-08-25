use std::{
    io::{self, BufRead, BufReader, Write},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use interprocess::local_socket::{ListenerNonblockingMode, ListenerOptions, Stream, prelude::*};

use crate::{
    config::Config,
    inference::ModelService,
    protocol::{MAX_MESSAGE_BYTES, Request, Response},
    transport::endpoint_name,
};

pub fn run(config: Config) -> Result<()> {
    let listener = ListenerOptions::new()
        .name(endpoint_name()?)
        .nonblocking(ListenerNonblockingMode::Accept)
        .try_overwrite(true)
        .create_sync()
        .context("failed to create the local IPC endpoint; another server may be running")?;
    let ttl = Duration::from_secs(config.model_ttl_seconds);
    let mut service = ModelService::new(config)?;
    let mut last_inference: Option<Instant> = None;

    loop {
        if should_unload(service.is_loaded(), last_inference, ttl, Instant::now()) {
            service.unload();
            last_inference = None;
        }

        match listener.accept() {
            Ok(connection) => {
                let outcome = handle_connection(connection, &mut service);
                match outcome {
                    Ok(HandleOutcome::Continue { inferred }) => {
                        if inferred {
                            last_inference = Some(Instant::now());
                        }
                    }
                    Ok(HandleOutcome::Shutdown) => break,
                    Err(error) => eprintln!("shellai server: {error:#}"),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error).context("local IPC accept failed"),
        }
    }
    Ok(())
}

fn should_unload(
    model_loaded: bool,
    last_inference: Option<Instant>,
    ttl: Duration,
    now: Instant,
) -> bool {
    model_loaded
        && last_inference.is_some_and(|last| ttl.is_zero() || now.duration_since(last) >= ttl)
}

enum HandleOutcome {
    Continue { inferred: bool },
    Shutdown,
}

fn handle_connection(connection: Stream, service: &mut ModelService) -> Result<HandleOutcome> {
    let mut connection = BufReader::new(connection);
    let mut line = String::new();
    connection.read_line(&mut line)?;
    anyhow::ensure!(
        !line.is_empty(),
        "client closed the connection without a request"
    );
    anyhow::ensure!(
        line.len() <= MAX_MESSAGE_BYTES,
        "client request is too large"
    );
    let request: Request = serde_json::from_str(&line).context("client sent invalid JSON")?;

    let (response, outcome) = match request {
        Request::Generate { prompt, context } => {
            let response = if prompt.trim().is_empty() {
                Response::failure("request cannot be empty", service.is_loaded())
            } else {
                match service.generate(&prompt, context.as_deref()) {
                    Ok(command) => Response::success(Some(command), true),
                    Err(error) => Response::failure(format!("{error:#}"), service.is_loaded()),
                }
            };
            (response, HandleOutcome::Continue { inferred: true })
        }
        Request::Status => (
            Response::success(None, service.is_loaded()),
            HandleOutcome::Continue { inferred: false },
        ),
        Request::Shutdown => (
            Response::success(None, service.is_loaded()),
            HandleOutcome::Shutdown,
        ),
    };

    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    connection.get_mut().write_all(&encoded)?;
    connection.get_mut().flush()?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unloads_only_after_idle_ttl() {
        let now = Instant::now();
        let recent = now - Duration::from_secs(30);
        let old = now - Duration::from_secs(61);
        let ttl = Duration::from_secs(60);

        assert!(!should_unload(true, Some(recent), ttl, now));
        assert!(should_unload(true, Some(old), ttl, now));
        assert!(!should_unload(false, Some(old), ttl, now));
        assert!(!should_unload(true, None, ttl, now));
        assert!(should_unload(true, Some(now), Duration::ZERO, now));
    }
}
