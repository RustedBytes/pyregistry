use async_trait::async_trait;
use pyregistry_application::{
    ApplicationError, VulnerabilityNotifier, VulnerablePackageNotification, severity_rank,
};
use reqwest::{Client, Url};
use serde::Serialize;
use std::time::Duration;

pub struct DiscordWebhookVulnerabilityNotifier {
    endpoint: Url,
    username: Option<String>,
    client: Client,
}

impl DiscordWebhookVulnerabilityNotifier {
    pub fn new(
        endpoint: impl AsRef<str>,
        username: Option<String>,
        timeout_seconds: u64,
    ) -> Result<Self, ApplicationError> {
        let endpoint = Url::parse(endpoint.as_ref()).map_err(|error| {
            ApplicationError::External(format!("invalid vulnerability webhook URL: {error}"))
        })?;
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|error| {
                ApplicationError::External(format!(
                    "could not build vulnerability webhook HTTP client: {error}"
                ))
            })?;

        Ok(Self {
            endpoint,
            username,
            client,
        })
    }
}

#[async_trait]
impl VulnerabilityNotifier for DiscordWebhookVulnerabilityNotifier {
    async fn notify_vulnerable_package(
        &self,
        notification: &VulnerablePackageNotification,
    ) -> Result<(), ApplicationError> {
        let payload =
            DiscordWebhookPayload::for_vulnerable_package(notification, self.username.as_deref());
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&payload)
            .send()
            .await
            .map_err(|error| {
                ApplicationError::External(format!("vulnerability webhook POST failed: {error}"))
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let body = response.text().await.unwrap_or_default();
        Err(ApplicationError::External(format!(
            "vulnerability webhook returned HTTP {status}: {}",
            truncate_response_body(&body)
        )))
    }
}

#[derive(Debug, Serialize)]
struct DiscordWebhookPayload {
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    embeds: Vec<DiscordEmbed>,
    allowed_mentions: DiscordAllowedMentions,
}

impl DiscordWebhookPayload {
    fn for_vulnerable_package(
        notification: &VulnerablePackageNotification,
        username: Option<&str>,
    ) -> Self {
        let title = "Vulnerable package detected".to_string();
        let package = format!("{}/{}", notification.tenant_slug, notification.project_name);
        let severity = notification
            .highest_severity
            .as_deref()
            .unwrap_or("UNKNOWN")
            .to_string();
        let fields = vec![
            DiscordEmbedField::inline("Tenant", &notification.tenant_slug),
            DiscordEmbedField::inline("Package", &notification.project_name),
            DiscordEmbedField::inline("Normalized name", &notification.normalized_name),
            DiscordEmbedField::inline("Scanned files", notification.scanned_file_count.to_string()),
            DiscordEmbedField::inline(
                "Vulnerable files",
                notification.vulnerable_file_count.to_string(),
            ),
            DiscordEmbedField::inline(
                "Advisory matches",
                notification.vulnerability_count.to_string(),
            ),
            DiscordEmbedField::inline("Highest severity", &severity),
        ];

        Self {
            content: format!("Vulnerable package detected: `{package}`"),
            username: username.map(ToOwned::to_owned),
            embeds: vec![DiscordEmbed {
                title,
                description: "Known vulnerability checks found advisory matches for this package."
                    .into(),
                color: severity_color(notification.highest_severity.as_deref()),
                fields,
            }],
            allowed_mentions: DiscordAllowedMentions { parse: Vec::new() },
        }
    }
}

#[derive(Debug, Serialize)]
struct DiscordEmbed {
    title: String,
    description: String,
    color: u32,
    fields: Vec<DiscordEmbedField>,
}

#[derive(Debug, Serialize)]
struct DiscordEmbedField {
    name: String,
    value: String,
    inline: bool,
}

impl DiscordEmbedField {
    fn inline(name: impl Into<String>, value: impl ToString) -> Self {
        Self {
            name: name.into(),
            value: value.to_string(),
            inline: true,
        }
    }
}

#[derive(Debug, Serialize)]
struct DiscordAllowedMentions {
    parse: Vec<String>,
}

fn severity_color(severity: Option<&str>) -> u32 {
    match severity.map(severity_rank).unwrap_or(0) {
        5 => 0xe74c3c,
        4 => 0xe67e22,
        3 => 0xf1c40f,
        2 => 0x3498db,
        1 => 0x95a5a6,
        _ => 0x7f8c8d,
    }
}

fn truncate_response_body(body: &str) -> String {
    const MAX_LEN: usize = 256;
    let trimmed = body.trim();
    if trimmed.chars().count() <= MAX_LEN {
        return trimmed.to_string();
    }
    let mut truncated = trimmed.chars().take(MAX_LEN).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn discord_payload_contains_vulnerable_package_summary() {
        let notification = VulnerablePackageNotification {
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            normalized_name: "demo-pkg".into(),
            scanned_file_count: 3,
            vulnerable_file_count: 2,
            vulnerability_count: 4,
            highest_severity: Some("CRITICAL".into()),
        };

        let payload =
            DiscordWebhookPayload::for_vulnerable_package(&notification, Some("Pyregistry"));
        let json = serde_json::to_value(payload).expect("payload json");

        assert_eq!(json["username"], "Pyregistry");
        assert_eq!(
            json["content"],
            "Vulnerable package detected: `acme/Demo_Pkg`"
        );
        assert_eq!(json["allowed_mentions"]["parse"], Value::Array(Vec::new()));
        assert_eq!(json["embeds"][0]["title"], "Vulnerable package detected");
        assert_eq!(json["embeds"][0]["color"], 0xe74c3c);
        assert!(
            json["embeds"][0]["fields"]
                .as_array()
                .is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|field| field["name"] == "Advisory matches" && field["value"] == "4")
                })
        );
    }

    #[test]
    fn truncates_long_webhook_response_bodies() {
        let body = "a".repeat(300);
        let truncated = truncate_response_body(&body);

        assert_eq!(truncated.chars().count(), 259);
        assert!(truncated.ends_with("..."));
    }
}
