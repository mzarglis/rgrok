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

    /// Delete the specified DNS records, attempting every ID even if one fails.
    pub async fn delete_records(&self, record_ids: &[String]) -> anyhow::Result<()> {
        let mut failures = Vec::new();

        for record_id in record_ids {
            if let Err(error) = self.delete_record(record_id).await {
                failures.push(format!("{record_id}: {error}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "failed to delete DNS records: {}",
                failures.join("; ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::routing::{delete as axum_delete, post as axum_post};
    use axum::{Json, Router};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct MockState {
        deleted_record_ids: Arc<Mutex<Vec<String>>>,
        failed_record_ids: Arc<HashSet<String>>,
    }

    async fn mock_create_dns_record() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "result": { "id": "rec-abc-123" }
        }))
    }

    async fn mock_delete_dns_record(
        State(state): State<MockState>,
        Path((_zone_id, record_id)): Path<(String, String)>,
    ) -> axum::http::StatusCode {
        state
            .deleted_record_ids
            .lock()
            .unwrap()
            .push(record_id.clone());
        if state.failed_record_ids.contains(&record_id) {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        } else {
            axum::http::StatusCode::OK
        }
    }

    fn mock_router(state: MockState) -> Router {
        Router::new()
            .route(
                "/zones/{zone_id}/dns_records",
                axum_post(mock_create_dns_record),
            )
            .route(
                "/zones/{zone_id}/dns_records/{record_id}",
                axum_delete(mock_delete_dns_record),
            )
            .with_state(state)
    }

    async fn start_mock_server(
        failed_record_ids: HashSet<String>,
    ) -> (u16, Arc<Mutex<Vec<String>>>) {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let deleted_record_ids = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            deleted_record_ids: deleted_record_ids.clone(),
            failed_record_ids: Arc::new(failed_record_ids),
        };
        tokio::spawn(async move {
            let _ = ready_tx.send(());
            axum::serve(listener, mock_router(state)).await.unwrap();
        });
        ready_rx.await.expect("mock server failed to start");
        (port, deleted_record_ids)
    }

    #[tokio::test]
    async fn test_create_a_record_returns_id() {
        let (port, _) = start_mock_server(HashSet::new()).await;
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
        let (port, _) = start_mock_server(HashSet::new()).await;
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
        let (port, _) = start_mock_server(HashSet::new()).await;
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
    async fn test_delete_records_only_deletes_owned_ids() {
        let (port, deleted_record_ids) = start_mock_server(HashSet::new()).await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        let owned_record_ids = vec!["txt-rec-owned-1".to_string(), "txt-rec-owned-2".to_string()];
        let result = client.delete_records(&owned_record_ids).await;
        assert!(result.is_ok());
        let deleted_record_ids = deleted_record_ids.lock().unwrap();
        assert_eq!(*deleted_record_ids, owned_record_ids);
        assert!(!deleted_record_ids
            .iter()
            .any(|id| id == "txt-rec-unrelated"));
    }

    #[tokio::test]
    async fn test_delete_records_attempts_all_ids_after_partial_failure() {
        let failed_record_ids = HashSet::from(["txt-rec-owned-2".to_string()]);
        let (port, deleted_record_ids) = start_mock_server(failed_record_ids).await;
        let client = CloudflareClient::with_base_url(
            "test-token".to_string(),
            "zone-123".to_string(),
            format!("http://127.0.0.1:{}", port),
        );

        let owned_record_ids = vec![
            "txt-rec-owned-1".to_string(),
            "txt-rec-owned-2".to_string(),
            "txt-rec-owned-3".to_string(),
        ];
        let result = client.delete_records(&owned_record_ids).await;
        assert!(result.is_err());
        assert_eq!(*deleted_record_ids.lock().unwrap(), owned_record_ids);
    }
}
