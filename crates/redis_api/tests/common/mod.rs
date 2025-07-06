use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::Value;

pub const BASE_URL: &str = "http://localhost:3000";

pub async fn get_test_base_url() -> String {
    BASE_URL.to_string()
}

pub struct TestContext {
    pub base_url: String,
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub admin_token: Option<String>,
}

impl TestContext {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
            auth_token: None,
            admin_token: None,
        }
    }

    pub async fn authenticate_admin(&mut self) -> Result<()> {
        let auth_payload = serde_json::json!({
            "username": "testadmin",
            "password": "testpassword123"
        });

        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&auth_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Authentication failed: {}", response.status()));
        }

        let auth_response: Value = response.json().await?;
        let access_token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?;

        self.admin_token = Some(access_token.to_string());
        Ok(())
    }

    pub async fn authenticate_user(&mut self) -> Result<()> {
        let auth_payload = serde_json::json!({
            "username": "testuser",
            "password": "testpassword123"
        });

        let response = self
            .client
            .post(&format!("{}/auth/login", self.base_url))
            .json(&auth_payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Authentication failed: {}", response.status()));
        }

        let auth_response: Value = response.json().await?;
        let access_token = auth_response["data"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No access token in response"))?;

        self.auth_token = Some(access_token.to_string());
        Ok(())
    }

    pub fn get_auth_header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = &self.auth_token {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            );
        }
        headers
    }

    pub fn get_admin_auth_header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = &self.admin_token {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            );
        }
        headers
    }

    pub async fn get_with_auth(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self
            .client
            .get(url)
            .headers(self.get_auth_header())
            .send()
            .await?)
    }

    pub async fn get_with_admin_auth(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self
            .client
            .get(url)
            .headers(self.get_admin_auth_header())
            .send()
            .await?)
    }

    pub async fn post_with_auth(&self, url: &str, body: &Value) -> Result<reqwest::Response> {
        Ok(self
            .client
            .post(url)
            .headers(self.get_auth_header())
            .json(body)
            .send()
            .await?)
    }

    pub async fn post_with_admin_auth(&self, url: &str, body: &Value) -> Result<reqwest::Response> {
        Ok(self
            .client
            .post(url)
            .headers(self.get_admin_auth_header())
            .json(body)
            .send()
            .await?)
    }

    pub async fn delete_with_auth(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self
            .client
            .delete(url)
            .headers(self.get_auth_header())
            .send()
            .await?)
    }

    pub async fn delete_with_admin_auth(&self, url: &str) -> Result<reqwest::Response> {
        Ok(self
            .client
            .delete(url)
            .headers(self.get_admin_auth_header())
            .send()
            .await?)
    }
}
