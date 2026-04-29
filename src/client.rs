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

    pub async fn put(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let bearer = self.ensure_token().await?;
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base_url, path)
        };

        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("PUT {} -> {}: {}", url, status, body);
        }

        let text = resp.text().await.unwrap_or_default();
        if text.is_empty() {
            Ok(serde_json::json!({"status": "ok"}))
        } else {
            serde_json::from_str(&text).with_context(|| format!("parsing PUT response from {url}"))
        }
    }

    pub async fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
        let bearer = self.ensure_token().await?;
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}", self.base_url, path)
        };

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        let status_code = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap_or_default();

        if !status_code.is_success() {
            bail!("POST {} -> {}: {}", url, status_code, text);
        }

        // For 201 Created, return location header if present
        if let Some(loc) = headers.get("location") {
            let loc_str = loc.to_str().unwrap_or("");
            if text.is_empty() {
                return Ok(serde_json::json!({"status": "created", "location": loc_str}));
            }
        }

        if text.is_empty() {
            Ok(serde_json::json!({"status": "ok"}))
        } else {
            serde_json::from_str(&text).with_context(|| format!("parsing POST response from {url}"))
        }
    }
}
