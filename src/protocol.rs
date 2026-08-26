use serde::{Deserialize, Serialize};

use crate::config::InferenceConfig;

pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Generate {
        prompt: String,
        context: Option<String>,
        #[serde(default)]
        system_prompt: Option<String>,
        #[serde(default)]
        workflow_id: Option<String>,
        #[serde(default)]
        stage: Option<String>,
        #[serde(default)]
        assistant_prefix: Option<String>,
        #[serde(default)]
        stop_after: Option<String>,
        #[serde(default)]
        inference_config: Option<InferenceConfig>,
    },
    Status,
    Shutdown,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub model_loaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<InferenceMetrics>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InferenceMetrics {
    pub request_id: String,
    pub workflow_id: Option<String>,
    pub stage: String,
    pub success: bool,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
    pub context_limit: u32,
    pub inference_ms: u64,
    pub rss_before_bytes: u64,
    pub rss_after_bytes: u64,
    pub peak_rss_bytes: u64,
    pub recorded_at_unix_ms: u128,
}

impl Response {
    pub fn success(
        command: Option<String>,
        model_loaded: bool,
        metrics: Option<InferenceMetrics>,
    ) -> Self {
        Self {
            ok: true,
            command,
            error: None,
            model_loaded,
            metrics,
        }
    }

    pub fn failure(
        error: impl Into<String>,
        model_loaded: bool,
        metrics: Option<InferenceMetrics>,
    ) -> Self {
        Self {
            ok: false,
            command: None,
            error: Some(error.into()),
            model_loaded,
            metrics,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let encoded = serde_json::to_string(&Request::Generate {
            prompt: "list files".into(),
            context: Some("ls".into()),
            system_prompt: None,
            workflow_id: Some("test-workflow".into()),
            stage: Some("search".into()),
            assistant_prefix: None,
            stop_after: None,
            inference_config: Some(crate::config::Config::default().inference_config()),
        })
        .unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded, Request::Generate { .. }));
    }
}
