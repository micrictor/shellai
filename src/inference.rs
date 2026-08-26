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

pub struct Generation {
    pub text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

pub struct GenerationOptions<'a> {
    pub current_line: Option<&'a str>,
    pub system_prompt: Option<&'a str>,
    pub assistant_prefix: Option<&'a str>,
    pub stop_after: Option<&'a str>,
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

    pub fn context_size(&self) -> u32 {
        self.config.context_size
    }

    pub fn unload(&mut self) {
        self.model.take();
    }

    pub fn generate(
        &mut self,
        request: &str,
        options: GenerationOptions<'_>,
    ) -> Result<Generation> {
        self.ensure_loaded()?;
        let model = self.model.as_ref().context("model was not loaded")?;
        generate_command(model, &self.backend, &self.config, request, options)
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
    options: GenerationOptions<'_>,
) -> Result<Generation> {
    let system = options.system_prompt.unwrap_or(
        "You are a helpful assistant that translates natural language to bash commands.",
    );
    let user = if options.system_prompt.is_some() {
        request.trim().to_owned()
    } else {
        match options
            .current_line
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            Some(line) => format!(
                "Current command line: {line}\nGenerate single Bash command: {}",
                request.trim()
            ),
            None => format!("Generate single Bash command: {}", request.trim()),
        }
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
    let prompt_tokens = u32::try_from(tokens.len()).context("prompt token count exceeds u32")?;
    let prefix = options.assistant_prefix.filter(|prefix| !prefix.is_empty());
    let prefix_tokens = prefix
        .map(|value| {
            model
                .str_to_token(value, AddBos::Never)
                .context("failed to tokenize the assistant prefix")
        })
        .transpose()?
        .unwrap_or_default();

    anyhow::ensure!(config.context_size > 0, "context_size must be nonzero");
    anyhow::ensure!(
        tokens.len() + prefix_tokens.len() < config.context_size as usize,
        "request is too long for the configured {} token context",
        config.context_size
    );
    let required_context = tokens
        .len()
        .saturating_add(prefix_tokens.len())
        .saturating_add(config.max_new_tokens as usize);
    let rounded_context = required_context.saturating_add(511) / 512 * 512;
    let active_context = rounded_context.max(512).min(config.context_size as usize);
    let context_size = NonZeroU32::new(u32::try_from(active_context)?)
        .context("active context size must be nonzero")?;

    let mut context_params = LlamaContextParams::default().with_n_ctx(Some(context_size));
    if let Some(threads) = config.threads {
        context_params = context_params
            .with_n_threads(threads)
            .with_n_threads_batch(threads);
    }
    let mut context = model
        .new_context(backend, context_params)
        .context("failed to create an inference context")?;
    const PROMPT_BATCH_TOKENS: usize = 2048;
    let mut batch = LlamaBatch::new(PROMPT_BATCH_TOKENS, 1);
    let last_index = tokens.len() - 1;
    for (chunk_index, chunk) in tokens.chunks(PROMPT_BATCH_TOKENS).enumerate() {
        batch.clear();
        let offset = chunk_index * PROMPT_BATCH_TOKENS;
        for (index, token) in chunk.iter().copied().enumerate() {
            let position = offset + index;
            batch.add(token, position as i32, &[0], position == last_index)?;
        }
        context
            .decode(&mut batch)
            .context("failed to evaluate the prompt")?;
    }

    anyhow::ensure!(config.top_k > 0, "top_k must be greater than zero");
    anyhow::ensure!(
        config.top_p > 0.0 && config.top_p <= 1.0,
        "top_p must be greater than zero and at most one"
    );
    anyhow::ensure!(
        config.temperature >= 0.0,
        "temperature must be zero or greater"
    );
    anyhow::ensure!(
        config.repeat_penalty > 0.0,
        "repeat_penalty must be greater than zero"
    );
    let mut sampler = LlamaSampler::chain_simple([
        LlamaSampler::penalties(-1, config.repeat_penalty, 0.0, 0.0),
        LlamaSampler::top_k(config.top_k),
        LlamaSampler::top_p(config.top_p, 1),
        LlamaSampler::temp(config.temperature),
        // LLAMA_DEFAULT_SEED asks llama.cpp to select a random seed.
        LlamaSampler::dist(config.seed.unwrap_or(u32::MAX)),
    ]);
    for token in tokens.iter().copied() {
        sampler.accept(token);
    }
    let mut decoder = encoding_rs::UTF_8.new_decoder();
    let mut output = String::new();
    let mut position = i32::try_from(tokens.len()).context("prompt position exceeds i32")?;
    let mut completion_tokens = 0;

    if let Some(prefix) = prefix {
        anyhow::ensure!(
            position as usize + prefix_tokens.len() < active_context,
            "assistant prefix is too long for the configured context"
        );
        for token in prefix_tokens.iter().copied() {
            sampler.accept(token);
            batch.clear();
            batch.add(token, position, &[0], true)?;
            position += 1;
            completion_tokens += 1;
            context
                .decode(&mut batch)
                .context("failed to evaluate the assistant prefix")?;
        }
        output.push_str(prefix);
    }

    let generated_start = output.len();
    let available = u32::try_from(active_context)?.saturating_sub(position as u32);
    let token_limit = config
        .max_new_tokens
        .saturating_sub(completion_tokens)
        .min(available);

    for _ in 0..token_limit {
        let token = sampler.sample(&context, batch.n_tokens() - 1);
        sampler.accept(token);
        if model.is_eog_token(token) {
            break;
        }
        completion_tokens += 1;
        output.push_str(&model.token_to_piece(token, &mut decoder, true, None)?);
        if let Some(stop) = options.stop_after.filter(|stop| !stop.is_empty())
            && let Some(index) = output[generated_start..].find(stop)
        {
            output.truncate(generated_start + index + stop.len());
            break;
        }
        batch.clear();
        batch.add(token, position, &[0], true)?;
        position += 1;
        context
            .decode(&mut batch)
            .context("failed to generate a token")?;
    }

    let command = clean_generated_command(&output);
    anyhow::ensure!(!command.is_empty(), "the model returned an empty command");
    Ok(Generation {
        text: command,
        prompt_tokens,
        completion_tokens,
    })
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
