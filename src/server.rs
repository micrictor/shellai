use std::{
    io::{self, BufRead, BufReader, Write},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use interprocess::local_socket::{ListenerNonblockingMode, ListenerOptions, Stream, prelude::*};

use crate::{
    config::Config,
    inference::{GenerationOptions, ModelService},
    metrics::{self, MemoryMonitor},
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
        Request::Generate {
            prompt,
            context,
            system_prompt,
            workflow_id,
            stage,
            assistant_prefix,
            stop_after,
            inference_config,
        } => {
            let stage = stage.unwrap_or_else(|| "zero_shot".into());
            let request_id = metrics::new_id("inference");
            let started = Instant::now();
            let memory_monitor = MemoryMonitor::start();
            if let Some(config) = inference_config {
                service.apply_inference_config(*config);
            }
            let response = if prompt.trim().is_empty() {
                let memory = memory_monitor.finish();
                let metrics = crate::protocol::InferenceMetrics {
                    request_id,
                    workflow_id,
                    stage,
                    success: false,
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    context_limit: service.context_size(),
                    inference_ms: duration_ms(started.elapsed()),
                    rss_before_bytes: memory.before,
                    rss_after_bytes: memory.after,
                    peak_rss_bytes: memory.peak,
                    recorded_at_unix_ms: metrics::unix_time_ms(),
                };
                record_server_metrics(&metrics);
                Response::failure(
                    "request cannot be empty",
                    service.is_loaded(),
                    Some(metrics),
                )
            } else {
                let result = service.generate(
                    &prompt,
                    GenerationOptions {
                        current_line: context.as_deref(),
                        system_prompt: system_prompt.as_deref(),
                        assistant_prefix: assistant_prefix.as_deref(),
                        stop_after: stop_after.as_deref(),
                    },
                );
                let memory = memory_monitor.finish();
                let (success, prompt_tokens, completion_tokens) = match &result {
                    Ok(generation) => {
                        (true, generation.prompt_tokens, generation.completion_tokens)
                    }
                    Err(_) => (false, 0, 0),
                };
                let metrics = crate::protocol::InferenceMetrics {
                    request_id,
                    workflow_id,
                    stage,
                    success,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens: prompt_tokens.saturating_add(completion_tokens),
                    context_limit: service.context_size(),
                    inference_ms: duration_ms(started.elapsed()),
                    rss_before_bytes: memory.before,
                    rss_after_bytes: memory.after,
                    peak_rss_bytes: memory.peak,
                    recorded_at_unix_ms: metrics::unix_time_ms(),
                };
                record_server_metrics(&metrics);
                match result {
                    Ok(generation) => Response::success(Some(generation.text), true, Some(metrics)),
                    Err(error) => {
                        Response::failure(format!("{error:#}"), service.is_loaded(), Some(metrics))
                    }
                }
            };
            (response, HandleOutcome::Continue { inferred: true })
        }
        Request::Status => (
            Response::success(None, service.is_loaded(), None),
            HandleOutcome::Continue { inferred: false },
        ),
        Request::Shutdown => (
            Response::success(None, service.is_loaded(), None),
            HandleOutcome::Shutdown,
        ),
    };

    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    connection.get_mut().write_all(&encoded)?;
    connection.get_mut().flush()?;
    Ok(outcome)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn record_server_metrics(metrics: &crate::protocol::InferenceMetrics) {
    if let Err(error) = metrics::append_server(metrics) {
        eprintln!("shellai server: failed to record metrics: {error:#}");
    }
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
