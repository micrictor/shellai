use std::{
    collections::HashMap,
    io::Read,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::{
    cli::WorkflowMode,
    config::{Config, InferenceConfig},
    metrics,
    protocol::{InferenceMetrics, Request},
    transport,
};

const LOCAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SEARCH_OUTPUT_BYTES: usize = 512 * 1024;

pub fn run(
    prompt: &str,
    context: Option<&str>,
    mode: WorkflowMode,
    cold_start: bool,
    config: &Config,
) -> Result<String> {
    let mut run = WorkflowRun::new(mode, config.inference_config());
    let result = match mode {
        WorkflowMode::Guided => run.guided(prompt, context, cold_start),
        WorkflowMode::ZeroShot => run.zero_shot(prompt, context, cold_start),
    };
    run.finish(result.is_ok());
    result
}

struct WorkflowRun {
    workflow_id: String,
    mode: WorkflowMode,
    started: Instant,
    inference_count: u32,
    total_prompt_tokens: u64,
    total_completion_tokens: u64,
    total_context_tokens: u64,
    server_inference_ms: u64,
    peak_server_rss_bytes: u64,
    discovery_command_ms: u64,
    help_command_ms: u64,
    inference_config: InferenceConfig,
}

struct InferenceOptions<'a> {
    context: Option<&'a str>,
    system_prompt: Option<&'a str>,
    assistant_prefix: Option<&'a str>,
    stop_after: Option<&'a str>,
    stage: &'a str,
    cold_start: bool,
}

#[derive(Serialize)]
struct ClientMetrics<'a> {
    workflow_id: &'a str,
    mode: &'static str,
    success: bool,
    inference_count: u32,
    total_prompt_tokens: u64,
    total_completion_tokens: u64,
    total_context_tokens: u64,
    server_inference_ms: u64,
    peak_server_rss_bytes: u64,
    discovery_command_ms: u64,
    help_command_ms: u64,
    end_to_end_ms: u64,
    recorded_at_unix_ms: u128,
}

impl WorkflowRun {
    fn new(mode: WorkflowMode, inference_config: InferenceConfig) -> Self {
        Self {
            workflow_id: metrics::new_id("workflow"),
            mode,
            started: Instant::now(),
            inference_count: 0,
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            total_context_tokens: 0,
            server_inference_ms: 0,
            peak_server_rss_bytes: 0,
            discovery_command_ms: 0,
            help_command_ms: 0,
            inference_config,
        }
    }

    fn zero_shot(
        &mut self,
        prompt: &str,
        context: Option<&str>,
        cold_start: bool,
    ) -> Result<String> {
        self.infer(
            prompt,
            InferenceOptions {
                context,
                system_prompt: None,
                assistant_prefix: None,
                stop_after: None,
                stage: "zero_shot",
                cold_start,
            },
        )
    }

    fn guided(&mut self, prompt: &str, context: Option<&str>, cold_start: bool) -> Result<String> {
        let mut search_prompt = discovery_prompt(prompt);
        let mut successful_search = None;
        let mut last_search_error = String::new();
        for attempt in 1..=3 {
            let discovery = self.infer(
                &search_prompt,
                InferenceOptions {
                    context: None,
                    system_prompt: Some(discovery_system_prompt()),
                    assistant_prefix: None,
                    stop_after: None,
                    stage: "command_search",
                    cold_start,
                },
            )?;
            let started = Instant::now();
            let result = run_discovery_command(&discovery).and_then(|results| {
                anyhow::ensure!(
                    !results.trim().is_empty(),
                    "the generated help search returned no results"
                );
                Ok(results)
            });
            self.discovery_command_ms = self
                .discovery_command_ms
                .saturating_add(duration_ms(started.elapsed()));
            match result {
                Ok(results) => {
                    successful_search = Some(results);
                    break;
                }
                Err(error) => {
                    last_search_error = format!(
                        "invalid discovery response from the model: {discovery:?}: {error:#}"
                    );
                    if attempt < 3 {
                        search_prompt = format!(
                            "The previous response {discovery:?} was rejected because {error:#}. Try again for this request: {prompt}. Return a broad man -k regular expression like the example, not a command that solves the request."
                        );
                    }
                }
            }
        }
        let search_results = successful_search.with_context(|| {
            format!("help discovery failed after 3 attempts: {last_search_error}")
        })?;
        let search_results = limit_search_output(search_results);
        let candidates = extract_candidates(&search_results);
        anyhow::ensure!(
            !candidates.is_empty(),
            "could not identify command names in the help search results"
        );

        let selection_prompt = format!(
            "User request:\n{prompt}\n\nHelp search results:\n{search_results}\n\nUser request again:\n{prompt}\n\nChoose the one or two command names from these results whose documentation is most useful. Return only the exact command names, one per line."
        );
        let mut current_selection_prompt = selection_prompt;
        let mut selected = None;
        let mut last_selection = String::new();
        let mut candidate_names: Vec<_> = candidates.values().cloned().collect();
        candidate_names.sort_unstable();
        for attempt in 1..=3 {
            let selection = self.infer(
                &current_selection_prompt,
                InferenceOptions {
                    context: None,
                    system_prompt: selection_system_prompt(),
                    assistant_prefix: None,
                    stop_after: None,
                    stage: "command_selection",
                    cold_start,
                },
            )?;
            match validate_selection(&selection, &candidates) {
                Ok(commands) => {
                    selected = Some(commands);
                    break;
                }
                Err(_) => {
                    last_selection = selection.clone();
                    if attempt < 3 {
                        current_selection_prompt = format!(
                            "User request: {prompt}\nValid command names: {}\nThe previous response {selection:?} was invalid. Generate a command using one or two names from the valid list so their full manuals can be loaded.",
                            candidate_names.join(", ")
                        );
                    }
                }
            }
        }
        let selected = selected.with_context(|| {
            format!(
                "model failed to select a command from the search results after 3 attempts; last response: {last_selection:?}"
            )
        })?;

        let started = Instant::now();
        let help_pages = load_help_pages(&selected)?;
        self.help_command_ms = duration_ms(started.elapsed());
        let context_note = context
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(String::new, |value| {
                format!("Existing command line to consider:\n{value}\n\n")
            });
        let final_prompt = format!(
            "User request:\n{prompt}\n\n{context_note}Complete reference documentation for the selected commands:\n{help_pages}\n\nUser request again:\n{prompt}\n\nGenerate exactly one command that fulfills the user request. Use the documented command behavior, return only the command, and do not include Markdown or an explanation."
        );
        self.infer(
            &final_prompt,
            InferenceOptions {
                context: None,
                system_prompt: Some(final_system_prompt()),
                assistant_prefix: None,
                stop_after: None,
                stage: "grounded_generation",
                cold_start,
            },
        )
    }

    fn infer(&mut self, prompt: &str, options: InferenceOptions<'_>) -> Result<String> {
        let request = Request::Generate {
            prompt: prompt.to_owned(),
            context: options.context.map(str::to_owned),
            system_prompt: options.system_prompt.map(str::to_owned),
            workflow_id: Some(self.workflow_id.clone()),
            stage: Some(options.stage.to_owned()),
            assistant_prefix: options.assistant_prefix.map(str::to_owned),
            stop_after: options.stop_after.map(str::to_owned),
            inference_config: Some(self.inference_config.clone()),
        };
        let response = transport::request(&request, options.cold_start)?;
        if let Some(metric) = &response.metrics {
            self.record_inference(metric);
        }
        anyhow::ensure!(
            response.ok,
            "{}",
            response.error.unwrap_or_else(|| "inference failed".into())
        );
        response
            .command
            .filter(|command| !command.trim().is_empty())
            .context("the model returned an empty response")
    }

    fn record_inference(&mut self, metric: &InferenceMetrics) {
        self.inference_count += 1;
        self.total_prompt_tokens += u64::from(metric.prompt_tokens);
        self.total_completion_tokens += u64::from(metric.completion_tokens);
        self.total_context_tokens += u64::from(metric.total_tokens);
        self.server_inference_ms = self.server_inference_ms.saturating_add(metric.inference_ms);
        self.peak_server_rss_bytes = self.peak_server_rss_bytes.max(metric.peak_rss_bytes);
    }

    fn finish(&self, success: bool) {
        let value = ClientMetrics {
            workflow_id: &self.workflow_id,
            mode: match self.mode {
                WorkflowMode::Guided => "guided",
                WorkflowMode::ZeroShot => "zero_shot",
            },
            success,
            inference_count: self.inference_count,
            total_prompt_tokens: self.total_prompt_tokens,
            total_completion_tokens: self.total_completion_tokens,
            total_context_tokens: self.total_context_tokens,
            server_inference_ms: self.server_inference_ms,
            peak_server_rss_bytes: self.peak_server_rss_bytes,
            discovery_command_ms: self.discovery_command_ms,
            help_command_ms: self.help_command_ms,
            end_to_end_ms: duration_ms(self.started.elapsed()),
            recorded_at_unix_ms: metrics::unix_time_ms(),
        };
        if let Err(error) = metrics::append_client(&value) {
            eprintln!("shellai: failed to record client metrics: {error:#}");
        }
    }
}

#[cfg(unix)]
fn discovery_system_prompt() -> &'static str {
    "Return only one broad apropos regular expression describing what relevant commands do. Use | between alternative descriptions. Do not output command names, shell commands, flags, paths, quotes, Markdown, or explanations. Example: search.*file|match.*pattern"
}

#[cfg(windows)]
fn discovery_system_prompt() -> &'static str {
    "Return only one PowerShell Get-Help name pattern such as *content*. Do not output a command, flags, paths, quotes, Markdown, or an explanation."
}

#[cfg(unix)]
fn discovery_prompt(prompt: &str) -> String {
    format!(
        "Write an apropos manual-description search expression for tools relevant to this request. Do not fulfill the request yet. Request: {prompt}"
    )
}

#[cfg(windows)]
fn discovery_prompt(prompt: &str) -> String {
    format!(
        "Write a Get-Help name search pattern for commands relevant to this request. Do not fulfill the request yet. Request: {prompt}"
    )
}

#[cfg(unix)]
fn final_system_prompt() -> &'static str {
    "You are a shell-command generator. Ground the answer in the supplied complete manual pages and use the selected documented commands. Match the requested output precisely: distinguish paths from file contents, and recurse when the scope is a directory. Return exactly one Bash command and no explanation."
}

#[cfg(unix)]
fn selection_system_prompt() -> Option<&'static str> {
    Some(
        "Select command names only from the supplied help-search results. Return one or two exact names and no explanation.",
    )
}

#[cfg(windows)]
fn selection_system_prompt() -> Option<&'static str> {
    Some(
        "Use the supplied PowerShell help-search results to choose one or two relevant command names.",
    )
}

#[cfg(windows)]
fn final_system_prompt() -> &'static str {
    "You are a PowerShell-command generator. Ground the answer in the supplied complete help pages and use the selected documented commands. Match the requested output precisely: distinguish paths from file contents, and recurse when the scope is a directory. Return exactly one PowerShell command and no explanation."
}

#[cfg(unix)]
fn run_discovery_command(generated: &str) -> Result<String> {
    let query = parse_man_search(generated)?;
    let mut command = Command::new("man");
    command.args(["-k", &query]);
    run_local_command(&mut command, "man -k")
}

#[cfg(windows)]
fn run_discovery_command(generated: &str) -> Result<String> {
    let query = parse_get_help_search(generated)?;
    let script = format!("Get-Help -Name '{query}'");
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    run_local_command(&mut command, "Get-Help")
}

#[cfg(unix)]
fn parse_man_search(generated: &str) -> Result<String> {
    let line = single_line(generated)?;
    let rest = line.strip_prefix("man -k ").unwrap_or(line);
    normalize_apropos_expression(strip_matching_quotes(rest.trim()))
}

#[cfg(unix)]
fn normalize_apropos_expression(value: &str) -> Result<String> {
    anyhow::ensure!(!value.is_empty(), "the model returned an empty man search");
    anyhow::ensure!(
        !value.contains(['\0', '\n', '\r', ';', '&', '<', '>', '`']),
        "man search contains unsupported command syntax"
    );
    let stopwords = [
        "a", "all", "an", "and", "command", "commands", "display", "every", "for", "in", "list",
        "of", "the", "to", "tool", "tools", "with",
    ];
    let mut expressions = Vec::new();
    for segment in value.split('|') {
        let mut words = Vec::new();
        for word in segment.split(|character: char| !character.is_ascii_alphabetic()) {
            let word = stem_search_word(word);
            if !word.is_empty() && !stopwords.contains(&word.as_str()) && !words.contains(&word) {
                words.push(word);
            }
        }
        let expression = match words.as_slice() {
            [] => continue,
            [word] => word.clone(),
            words => format!("{}.*{}", words[0], words[words.len() - 1]),
        };
        if !expressions.contains(&expression) {
            expressions.push(expression);
        }
        if expressions.len() == 8 {
            break;
        }
    }
    anyhow::ensure!(
        !expressions.is_empty(),
        "the model returned no usable manual-description terms"
    );
    Ok(expressions.join("|"))
}

#[cfg(unix)]
fn stem_search_word(word: &str) -> String {
    let mut word = word.to_ascii_lowercase();
    if word.len() > 5 && word.ends_with("ing") {
        word.truncate(word.len() - 3);
    } else if word.len() > 4 && word.ends_with("ies") {
        word.truncate(word.len() - 3);
        word.push('y');
    } else if word.len() > 4
        && ["ses", "xes", "zes", "ches", "shes"]
            .iter()
            .any(|ending| word.ends_with(ending))
    {
        word.truncate(word.len() - 2);
    } else if word.len() > 3 && word.ends_with('s') {
        word.pop();
    }
    word
}

#[cfg(windows)]
fn parse_get_help_search(generated: &str) -> Result<String> {
    let line = single_line(generated)?;
    if !line.to_ascii_lowercase().starts_with("get-help ") {
        let query = strip_matching_quotes(line);
        anyhow::ensure!(
            query.chars().all(|character| {
                character.is_ascii_alphanumeric() || "*?-_.".contains(character)
            }),
            "Get-Help search contains unsupported characters"
        );
        return Ok(query.to_owned());
    }
    let mut words = line.split_ascii_whitespace();
    anyhow::ensure!(
        words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("Get-Help")),
        "the model did not return a Get-Help command"
    );
    anyhow::ensure!(
        words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("-Name")),
        "the Get-Help command must use -Name"
    );
    let query = strip_matching_quotes(words.next().context("Get-Help search is empty")?);
    anyhow::ensure!(
        words.next().is_none(),
        "Get-Help search has unexpected arguments"
    );
    anyhow::ensure!(
        query
            .chars()
            .all(|character| { character.is_ascii_alphanumeric() || "*?-_.".contains(character) }),
        "Get-Help search contains unsupported characters"
    );
    Ok(query.to_owned())
}

fn single_line(value: &str) -> Result<&str> {
    let trimmed = value.trim();
    anyhow::ensure!(
        !trimmed.contains(['\n', '\r']),
        "the model returned more than one command"
    );
    Ok(trimmed)
}

fn strip_matching_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn limit_search_output(mut output: String) -> String {
    if output.len() <= MAX_SEARCH_OUTPUT_BYTES {
        return output;
    }
    let mut boundary = MAX_SEARCH_OUTPUT_BYTES;
    while !output.is_char_boundary(boundary) {
        boundary -= 1;
    }
    output.truncate(boundary);
    output.push_str("\n[search results truncated by shellai]\n");
    output
}

#[cfg(unix)]
fn extract_candidates(search_results: &str) -> HashMap<String, String> {
    let mut candidates = HashMap::new();
    for line in search_results.lines() {
        let Some((names, _)) = line.split_once(" (") else {
            continue;
        };
        for name in names
            .split(',')
            .map(str::trim)
            .filter(|name| valid_name(name))
        {
            candidates
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| name.to_owned());
        }
    }
    candidates
}

#[cfg(windows)]
fn extract_candidates(search_results: &str) -> HashMap<String, String> {
    let mut candidates = HashMap::new();
    for line in search_results.lines() {
        if let Some(name) = line.split_ascii_whitespace().next().filter(|name| {
            name.contains('-') && valid_name(name) && !name.eq_ignore_ascii_case("Name")
        }) {
            candidates
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| name.to_owned());
        }
    }
    candidates
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.+".contains(character))
}

fn validate_selection(
    generated: &str,
    candidates: &HashMap<String, String>,
) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    for token in generated
        .split(|character: char| !(character.is_ascii_alphanumeric() || "-_.+".contains(character)))
    {
        let key = token.to_ascii_lowercase();
        if let Some(name) = candidates.get(&key)
            && !selected.iter().any(|existing| existing == name)
        {
            selected.push(name.clone());
            if selected.len() == 2 {
                break;
            }
        }
    }
    anyhow::ensure!(
        !selected.is_empty(),
        "the model did not select a command from the search results"
    );
    Ok(selected)
}

#[cfg(unix)]
fn load_help_pages(selected: &[String]) -> Result<String> {
    let mut pages = String::new();
    for name in selected {
        let mut command = Command::new("man");
        command
            .arg(name)
            .env("MANPAGER", "cat")
            .env("PAGER", "cat")
            .env("MANWIDTH", "100")
            .env("TERM", "dumb");
        let page = run_local_command(&mut command, &format!("man {name}"))?;
        pages.push_str(&format!("\n===== man {name} =====\n"));
        pages.push_str(&remove_overstrikes(&page));
    }
    Ok(pages)
}

#[cfg(windows)]
fn load_help_pages(selected: &[String]) -> Result<String> {
    let mut pages = String::new();
    for name in selected {
        let script = format!("Get-Help -Full -Name '{name}' | Out-String -Width 240");
        let mut command = Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        let page = run_local_command(&mut command, &format!("Get-Help -Full {name}"))?;
        pages.push_str(&format!("\n===== Get-Help -Full {name} =====\n"));
        pages.push_str(&page);
    }
    Ok(pages)
}

#[cfg(unix)]
fn remove_overstrikes(value: &str) -> String {
    let mut output = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        if byte == 8 {
            output.pop();
        } else {
            output.push(byte);
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn run_local_command(command: &mut Command, label: &str) -> Result<String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to run {label}"))?;
    let mut stdout = child.stdout.take().context("failed to capture stdout")?;
    let mut stderr = child.stderr.take().context("failed to capture stderr")?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= LOCAL_COMMAND_TIMEOUT {
            child.kill().ok();
            child.wait().ok();
            anyhow::bail!("{label} timed out after 15 seconds");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} stderr reader panicked"))??;
    command_result(label, status, stdout, stderr)
}

fn command_result(
    label: &str,
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<String> {
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    if status.success() || !stdout.trim().is_empty() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&stderr);
    anyhow::bail!("{label} failed: {}", stderr.trim())
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn normalizes_a_single_manual_description_search() {
        assert_eq!(
            parse_man_search("man -k 'file contents'").unwrap(),
            "file.*content"
        );
        assert_eq!(
            parse_man_search(
                "| List files with \"root\" in /etc | Search for string \"root\" across files | Display matching patterns |"
            )
            .unwrap(),
            "file.*etc|search.*file|match.*pattern"
        );
        assert_eq!(parse_man_search("find /tmp").unwrap(), "find.*tmp");
        assert!(parse_man_search("man -k file\nwhoami").is_err());
    }

    #[test]
    fn validates_selection_against_search_results() {
        let candidates = HashMap::from([
            ("find".to_owned(), "find".to_owned()),
            ("grep".to_owned(), "grep".to_owned()),
        ]);
        assert_eq!(
            validate_selection("grep\nfind", &candidates).unwrap(),
            ["grep", "find"]
        );
        assert!(validate_selection("awk", &candidates).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn strips_manpage_overstrikes() {
        assert_eq!(remove_overstrikes("g\u{8}gr\u{8}re\u{8}ep\u{8}p"), "grep");
    }
}
