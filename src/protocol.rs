use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Generate {
        prompt: String,
        context: Option<String>,
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
}

impl Response {
    pub fn success(command: Option<String>, model_loaded: bool) -> Self {
        Self {
            ok: true,
            command,
            error: None,
            model_loaded,
        }
    }

    pub fn failure(error: impl Into<String>, model_loaded: bool) -> Self {
        Self {
            ok: false,
            command: None,
            error: Some(error.into()),
            model_loaded,
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
        })
        .unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(decoded, Request::Generate { .. }));
    }
}
