use reqwest::Client;
use tracing::info;

/// Client for interacting with the Cloudflare DNS API
#[allow(dead_code)]
pub struct CloudflareClient {
    client: Client,
    api_token: String,
    zone_id: String,
    base_url: String,
}

#[allow(dead_code)]
impl CloudflareClient {
    pub fn new(api_token: String, zone_id: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(api_token: String, zone_id: String, base_url: String) -> Self {
        Self {
            client: Client::new(),
            api_token,
            zone_id,
            base_url,
        }
    }

    /// Create an A record for a tunnel subdomain
    pub async fn create_record(
        &self,
        subdomain: &str,
        ip: &str,
        ttl: u32,
    ) -> anyhow::Result<String> {
        let resp = self
            .client
            .post(format!(
                "{}/zones/{}/dns_records",
                self.base_url, self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "A",
                "name": subdomain,
                "content": ip,
                "ttl": ttl,
                "proxied": false
            }))
            .send()
            .await?
            .error_for_status()?;

        let body: serde_json::Value = resp.json().await?;
        let record_id = body["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing record ID in response"))?
            .to_string();

        info!(subdomain, record_id = %record_id, "Created DNS record");
        Ok(record_id)
    }

    /// Delete a DNS record by ID
    pub async fn delete_record(&self, record_id: &str) -> anyhow::Result<()> {
        self.client
            .delete(format!(
                "{}/zones/{}/dns_records/{}",
                self.base_url, self.zone_id, record_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;

        info!(record_id, "Deleted DNS record");
        Ok(())
    }

    /// Create a TXT record (used for ACME DNS-01 challenges)
    pub async fn create_txt_record(&self, name: &str, value: &str) -> anyhow::Result<String> {
        let resp = self
            .client
            .post(format!(
                "{}/zones/{}/dns_records",
                self.base_url, self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": 120
            }))
            .send()
            .await?
            .error_for_status()?;

        let body: serde_json::Value = resp.json().await?;
        let record_id = body["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing record ID in response"))?
            .to_string();

        info!(name, record_id = %record_id, "Created TXT record");
        Ok(record_id)
    }

    /// Delete TXT records by name (for ACME cleanup)
    pub async fn delete_txt_records(&self, name: &str) -> anyhow::Result<()> {
        // List records with the given name
        let resp = self
            .client
            .get(format!(
                "{}/zones/{}/dns_records",
                self.base_url, self.zone_id
            ))
            .bearer_auth(&self.api_token)
            .query(&[("type", "TXT"), ("name", name)])
            .send()
            .await?
            .error_for_status()?;

        let body: serde_json::Value = resp.json().await?;
        if let Some(records) = body["result"].as_array() {
            for record in records {
                if let Some(id) = record["id"].as_str() {
                    self.delete_record(id).await?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::routing::{delete as axum_delete, post as axum_post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockState {
        delete_count: Arc<AtomicU32>,
    }

    async fn mock_create_dns_record() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "result": { "id": "rec-abc-123" }
        }))
    }

    async fn mock_delete_dns_record(
        State(state): State<MockState>,
        Path((_zone_id, _record_id)): Path<(String, String)>,
    ) -> axum::http::StatusCode {
        state.delete_count.fetch_add(1, Ordering::SeqCst);
        axum::http::StatusCode::OK
    }

    async fn mock_list_txt_records(
        Query(params): Query<HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        if params.get("type").map(|s| s.as_str()) == Some("TXT") {
            Json(serde_json::json!({
                "result": [
                    { "id": "txt-rec-1" },
                    { "id": "txt-rec-2" }
                ]
            }))
        } else {
            Json(serde_json::json!({ "result": [] }))
        }
    }

    fn mock_router(state: MockState) -> Router {
        Router::new()
            .route(
                "/zones/{zone_id}/dns_records",
                axum_post(mock_create_dns_record).get(mock_list_txt_records),
            )
            .route(
                "/zones/{zone_id}/dns_records/{record_id}",
                axum_delete(mock_delete_dns_record),
            )
            .with_state(state)
    }

    async fn start_mock_server() -> (u16, Arc<AtomicU32>) {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let delete_count = Arc::new(AtomicU32::new(0));
        let state = MockState {
            delete_count: delete_count.clone(),
        };
        tokio::spawn(async move {
            let _ = ready_tx.send(());
            axum::serve(listener, mock_router(state)).await.unwrap();
        });
        ready_rx.await.expect("mock server failed to start");
        (port, delete_count)
    }

    #[tokio::test]
    async fn test_create_a_record_returns_id() {
        let (port, _) = start_mock_server().await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        let record_id = client
            .create_record("test-sub", "1.2.3.4", 120)
            .await
            .unwrap();
        assert_eq!(record_id, "rec-abc-123");
    }

    #[tokio::test]
    async fn test_delete_record_succeeds() {
        let (port, _) = start_mock_server().await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        let result = client.delete_record("rec-abc-123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_txt_record_returns_id() {
        let (port, _) = start_mock_server().await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        let record_id = client
            .create_txt_record("_acme-challenge.test", "challenge-token")
            .await
            .unwrap();
        assert_eq!(record_id, "rec-abc-123");
    }

    #[tokio::test]
    async fn test_delete_txt_records_cleans_up_all() {
        let (port, delete_count) = start_mock_server().await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        // delete_txt_records lists TXT records then deletes each one
        let result = client.delete_txt_records("_acme-challenge.test").await;
        assert!(result.is_ok());
        assert_eq!(
            delete_count.load(Ordering::SeqCst),
            2,
            "should have deleted 2 TXT records"
        );
    }
}
