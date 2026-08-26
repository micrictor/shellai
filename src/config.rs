use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

pub const DEFAULT_REPOSITORY: &str = "micrictor/gemma-3-270m-it-ft-bash-GGUF";
pub const DEFAULT_MODEL_FILE: &str = "gemma-3-270m-it-ft-bash-Q8_0.gguf";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    /// A local GGUF path. When set, repository and model_file are ignored.
    pub model_path: Option<PathBuf>,
    pub repository: String,
    pub model_file: String,
    pub model_ttl_seconds: u64,
    pub context_size: u32,
    pub max_new_tokens: u32,
    pub threads: Option<i32>,
    pub gpu_layers: u32,
    /// Transformers-compatible sampling controls from generation_config.json.
    pub top_k: i32,
    pub top_p: f32,
    /// None requests a fresh random seed from llama.cpp for each sampler.
    pub seed: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            model_path: None,
            repository: DEFAULT_REPOSITORY.into(),
            model_file: DEFAULT_MODEL_FILE.into(),
            model_ttl_seconds: 60,
            // Gemma 3 advertises a 32K context. The guided workflow needs the
            // room because its final stage includes complete help pages.
            context_size: 32768,
            max_new_tokens: 256,
            threads: None,
            gpu_layers: 999,
            top_k: 64,
            top_p: 0.95,
            seed: None,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let mut config = if path.exists() {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?
        } else {
            Self::default()
        };

        if let Some(value) = std::env::var_os("SHELLAI_MODEL") {
            config.model_path = Some(value.into());
        }
        if let Ok(value) = std::env::var("SHELLAI_MODEL_TTL") {
            config.model_ttl_seconds = value
                .parse()
                .context("SHELLAI_MODEL_TTL must be an integer number of seconds")?;
        }
        Ok(config)
    }

    pub fn path() -> Result<PathBuf> {
        Ok(project_dirs()?.config_dir().join("config.toml"))
    }

    pub fn cache_dir() -> Result<PathBuf> {
        Ok(project_dirs()?.cache_dir().to_path_buf())
    }

    pub fn write_default_if_missing() -> Result<PathBuf> {
        let path = Self::path()?;
        if !path.exists() {
            let parent = path.parent().context("config path has no parent")?;
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            let text = toml::to_string_pretty(&Self::default())?;
            fs::write(&path, text)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
        Ok(path)
    }
}

fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("dev", "micrictor", "shellai")
        .context("could not determine the per-user shellai directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_select_published_q8_0() {
        let config = Config::default();
        assert_eq!(config.repository, DEFAULT_REPOSITORY);
        assert_eq!(config.model_file, DEFAULT_MODEL_FILE);
        assert_eq!(config.model_ttl_seconds, 60);
        assert_eq!(config.context_size, 32768);
        assert_eq!(config.top_k, 64);
        assert_eq!(config.top_p, 0.95);
        assert_eq!(config.seed, None);
    }
}
