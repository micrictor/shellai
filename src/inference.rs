use std::{num::NonZeroU32, path::PathBuf};

use anyhow::{Context, Result};
use hf_hub::api::sync::ApiBuilder;
use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{AddBos, LlamaChatMessage, LlamaModel, params::LlamaModelParams},
    sampling::LlamaSampler,
};

use crate::config::Config;

pub struct ModelService {
    config: Config,
    backend: LlamaBackend,
    model: Option<LlamaModel>,
}

impl ModelService {
    pub fn new(config: Config) -> Result<Self> {
        let backend = LlamaBackend::init().context("failed to initialize libllama")?;
        Ok(Self {
            config,
            backend,
            model: None,
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.model.is_some()
    }

    pub fn unload(&mut self) {
        self.model.take();
    }

    pub fn generate(&mut self, request: &str, current_line: Option<&str>) -> Result<String> {
        self.ensure_loaded()?;
        let model = self.model.as_ref().context("model was not loaded")?;
        generate_command(model, &self.backend, &self.config, request, current_line)
    }

    fn ensure_loaded(&mut self) -> Result<()> {
        if self.model.is_none() {
            let path = resolve_model_path(&self.config)?;
            let params = LlamaModelParams::default().with_n_gpu_layers(self.config.gpu_layers);
            self.model = Some(
                LlamaModel::load_from_file(&self.backend, &path, &params)
                    .with_context(|| format!("failed to load GGUF {}", path.display()))?,
            );
        }
        Ok(())
    }
}

pub fn resolve_model_path(config: &Config) -> Result<PathBuf> {
    if let Some(path) = &config.model_path {
        anyhow::ensure!(
            path.is_file(),
            "configured GGUF does not exist: {}",
            path.display()
        );
        return Ok(path.clone());
    }

    let (owner, name) = config.repository.split_once('/').with_context(|| {
        format!(
            "repository must have owner/name form, got {:?}",
            config.repository
        )
    })?;
    let client = ApiBuilder::new()
        .with_progress(true)
        .build()
        .context("failed to initialize the Hugging Face client")?;
    client
        .model(format!("{owner}/{name}"))
        .get(&config.model_file)
        .with_context(|| {
            format!(
                "failed to download {}/{}; accept the Gemma license and authenticate with HF_TOKEN or `hf auth login`",
                config.repository, config.model_file
            )
        })
}

fn generate_command(
    model: &LlamaModel,
    backend: &LlamaBackend,
    config: &Config,
    request: &str,
    current_line: Option<&str>,
) -> Result<String> {
    let system = "You are a helpful assistant that translates natural language to bash commands.";
    let user = match current_line.map(str::trim).filter(|line| !line.is_empty()) {
        Some(line) => format!(
            "Current command line: {line}\nGenerate single Bash command: {}",
            request.trim()
        ),
        None => format!("Generate single Bash command: {}", request.trim()),
    };
    let messages = [
        LlamaChatMessage::new("system".into(), system.into())?,
        LlamaChatMessage::new("user".into(), user)?,
    ];
    let template = model
        .chat_template(None)
        .context("the GGUF does not contain a usable chat template")?;
    let prompt = model
        .apply_chat_template(&template, &messages, true)
        .context("failed to apply the model chat template")?;
    let tokens = model
        .str_to_token(&prompt, AddBos::Never)
        .context("failed to tokenize the request")?;

    let context_size =
        NonZeroU32::new(config.context_size).context("context_size must be nonzero")?;
    anyhow::ensure!(
        tokens.len() < config.context_size as usize,
        "request is too long for the configured {} token context",
        config.context_size
    );

    let mut context_params = LlamaContextParams::default().with_n_ctx(Some(context_size));
    if let Some(threads) = config.threads {
        context_params = context_params
            .with_n_threads(threads)
            .with_n_threads_batch(threads);
    }
    let mut context = model
        .new_context(backend, context_params)
        .context("failed to create an inference context")?;
    let mut batch = LlamaBatch::new(config.context_size as usize, 1);
    let last_index = tokens.len() - 1;
    for (index, token) in tokens.into_iter().enumerate() {
        batch.add(token, index as i32, &[0], index == last_index)?;
    }
    context
        .decode(&mut batch)
        .context("failed to evaluate the prompt")?;

    let mut sampler = LlamaSampler::greedy();
    let mut decoder = encoding_rs::UTF_8.new_decoder();
    let mut output = String::new();
    let mut position = batch.n_tokens();
    let available = config.context_size.saturating_sub(position as u32);
    let token_limit = config.max_new_tokens.min(available);

    for _ in 0..token_limit {
        let token = sampler.sample(&context, batch.n_tokens() - 1);
        sampler.accept(token);
        if model.is_eog_token(token) {
            break;
        }
        output.push_str(&model.token_to_piece(token, &mut decoder, true, None)?);
        batch.clear();
        batch.add(token, position, &[0], true)?;
        position += 1;
        context
            .decode(&mut batch)
            .context("failed to generate a token")?;
    }

    let command = clean_generated_command(&output);
    anyhow::ensure!(!command.is_empty(), "the model returned an empty command");
    Ok(command)
}

pub(crate) fn clean_generated_command(output: &str) -> String {
    let trimmed = output.trim();
    let unwrapped = if let Some(rest) = trimmed
        .strip_prefix("```bash")
        .or_else(|| trimmed.strip_prefix("```sh"))
        .or_else(|| trimmed.strip_prefix("```zsh"))
        .or_else(|| trimmed.strip_prefix("```"))
    {
        rest.strip_suffix("```").unwrap_or(rest).trim()
    } else {
        trimmed
    };
    unwrapped
        .replace(['“', '”'], "\"")
        .replace(['‘', '’'], "'")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_markdown_fence() {
        assert_eq!(clean_generated_command("```bash\nls -la\n```"), "ls -la");
    }

    #[test]
    fn normalizes_smart_quotes() {
        assert_eq!(clean_generated_command("echo “hello”"), "echo \"hello\"");
    }
}
