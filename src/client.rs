use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Deserialize)]
struct AuthResponse {
    #[serde(rename = "bearerToken")]
    bearer_token: String,
    #[serde(rename = "expiresInMilliseconds")]
    expires_in_ms: u64,
}

struct TokenState {
    bearer: String,
    expires_at: std::time::Instant,
}

pub struct BlackDuckClient {
    base_url: String,
    api_token: String,
    http: Client,
    token_state: Arc<RwLock<Option<TokenState>>>,
}

impl BlackDuckClient {
    pub fn from_env() -> Result<Self> {
        let base_url = std::env::var("BD_URL")
            .or_else(|_| std::env::var("POLARIS_URL"))
            .context("BD_URL or POLARIS_URL must be set")?;
        let api_token = std::env::var("BD_TOKEN")
            .or_else(|_| std::env::var("POLARIS_API_TOKEN"))
            .context("BD_TOKEN or POLARIS_API_TOKEN must be set")?;

        // Allow self-signed certs for corp instances
        let http = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token,
            http,
            token_state: Arc::new(RwLock::new(None)),
        })
    }

    async fn ensure_token(&self) -> Result<String> {
        // Check existing token
        {
            let state = self.token_state.read().await;
            if let Some(ref ts) = *state {
                // Refresh 60s before expiry
                if ts.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60) {
                    return Ok(ts.bearer.clone());
                }
            }
        }

        // Acquire new token
        let url = format!("{}/api/tokens/authenticate", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("token {}", self.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .context("Failed to authenticate with BlackDuck")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Auth failed ({}): {}", status, body);
        }

        let auth: AuthResponse = resp.json().await.context("Failed to parse auth response")?;
        let expires_at =
            std::time::Instant::now() + std::time::Duration::from_millis(auth.expires_in_ms);
        let bearer = auth.bearer_token.clone();

        {
            let mut state = self.token_state.write().await;
            *state = Some(TokenState {
                bearer: auth.bearer_token,
                expires_at,
            });
        }

        Ok(bearer)
    }

    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let bearer = self.ensure_token().await?;
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base_url, path)
        };

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("GET {} -> {}: {}", url, status, body);
        }

        resp.json().await.with_context(|| format!("parsing response from {url}"))
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
