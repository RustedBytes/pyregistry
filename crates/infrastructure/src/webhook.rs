use async_trait::async_trait;
use pyregistry_application::{
    ApplicationError, PackagePublishEventKind, PackagePublishNotification, PackagePublishNotifier,
    VulnerabilityNotifier, VulnerablePackageNotification, WheelAuditFindingNotification,
    WheelAuditNotifier, severity_rank,
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

#[async_trait]
impl WheelAuditNotifier for DiscordWebhookVulnerabilityNotifier {
    async fn notify_wheel_audit_findings(
        &self,
        notification: &WheelAuditFindingNotification,
    ) -> Result<(), ApplicationError> {
        let payload =
            DiscordWebhookPayload::for_wheel_audit_findings(notification, self.username.as_deref());
        post_webhook_payload(&self.client, self.endpoint.clone(), &payload).await
    }
}

#[async_trait]
impl PackagePublishNotifier for DiscordWebhookVulnerabilityNotifier {
    async fn notify_package_publish(
        &self,
        notification: &PackagePublishNotification,
    ) -> Result<(), ApplicationError> {
        let payload =
            DiscordWebhookPayload::for_package_publish(notification, self.username.as_deref());
        post_webhook_payload(&self.client, self.endpoint.clone(), &payload).await
    }
}

async fn post_webhook_payload(
    client: &Client,
    endpoint: Url,
    payload: &DiscordWebhookPayload,
) -> Result<(), ApplicationError> {
    let response = client
        .post(endpoint)
        .json(payload)
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

    fn for_wheel_audit_findings(
        notification: &WheelAuditFindingNotification,
        username: Option<&str>,
    ) -> Self {
        let package = format!(
            "{}/{} {}",
            notification.tenant_slug, notification.project_name, notification.version
        );
        let mut fields = vec![
            DiscordEmbedField::inline("Tenant", &notification.tenant_slug),
            DiscordEmbedField::inline("Package", &notification.project_name),
            DiscordEmbedField::inline("Version", &notification.version),
            DiscordEmbedField::inline("Wheel", &notification.wheel_filename),
            DiscordEmbedField::inline("Scanned files", notification.scanned_file_count.to_string()),
            DiscordEmbedField::inline("Findings", notification.findings.len().to_string()),
        ];

        if let Some(error) = &notification.source_security_scan_error {
            fields.push(DiscordEmbedField::new(
                "Source scan warning",
                truncate_field_value(error),
                false,
            ));
        }
        if let Some(error) = &notification.virus_scan_error {
            fields.push(DiscordEmbedField::new(
                "Virus scan warning",
                truncate_field_value(error),
                false,
            ));
        }

        let finding_summary = notification
            .findings
            .iter()
            .take(8)
            .map(format_wheel_finding)
            .collect::<Vec<_>>()
            .join("\n");
        if !finding_summary.is_empty() {
            fields.push(DiscordEmbedField::new(
                "Finding summary",
                truncate_field_value(&finding_summary),
                false,
            ));
        }

        Self {
            content: format!(
                "Wheel security findings detected: `{package}` `{}`",
                notification.wheel_filename
            ),
            username: username.map(ToOwned::to_owned),
            embeds: vec![DiscordEmbed {
                title: "Wheel security findings detected".into(),
                description:
                    "The mirrored wheel update scan found suspicious install-time signals.".into(),
                color: 0xe67e22,
                fields,
            }],
            allowed_mentions: DiscordAllowedMentions { parse: Vec::new() },
        }
    }

    fn for_package_publish(
        notification: &PackagePublishNotification,
        username: Option<&str>,
    ) -> Self {
        let (title, description, color) = match notification.kind {
            PackagePublishEventKind::NewPackage => (
                "New package published",
                "A new package was pushed into the registry.",
                0x2ecc71,
            ),
            PackagePublishEventKind::NewVersion => (
                "New package version published",
                "A new version was added to an existing package.",
                0x3498db,
            ),
        };
        let package = format!(
            "{}/{} {}",
            notification.tenant_slug, notification.project_name, notification.version
        );
        let fields = vec![
            DiscordEmbedField::inline("Tenant", &notification.tenant_slug),
            DiscordEmbedField::inline("Package", &notification.project_name),
            DiscordEmbedField::inline("Normalized name", &notification.normalized_name),
            DiscordEmbedField::inline("Version", &notification.version),
            DiscordEmbedField::inline("File", &notification.filename),
            DiscordEmbedField::inline("Size", notification.size_bytes.to_string()),
            DiscordEmbedField::inline("SHA256", &notification.sha256),
        ];

        Self {
            content: format!("{title}: `{package}`"),
            username: username.map(ToOwned::to_owned),
            embeds: vec![DiscordEmbed {
                title: title.into(),
                description: description.into(),
                color,
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
    fn new(name: impl Into<String>, value: impl ToString, inline: bool) -> Self {
        Self {
            name: name.into(),
            value: value.to_string(),
            inline,
        }
    }

    fn inline(name: impl Into<String>, value: impl ToString) -> Self {
        Self::new(name, value, true)
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

fn truncate_field_value(value: &str) -> String {
    const MAX_LEN: usize = 1000;
    let trimmed = value.trim();
    if trimmed.chars().count() <= MAX_LEN {
        return trimmed.to_string();
    }
    let mut truncated = trimmed.chars().take(MAX_LEN).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn format_wheel_finding(finding: &pyregistry_application::WheelAuditFinding) -> String {
    let path = finding.path.as_deref().unwrap_or("archive");
    let evidence = if finding.evidence.is_empty() {
        String::new()
    } else {
        format!(" ({})", finding.evidence.join(", "))
    };
    format!(
        "- {:?}: {}: {}{}",
        finding.kind, path, finding.summary, evidence
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyregistry_application::{WheelAuditFinding, WheelAuditFindingKind};
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
    fn discord_payload_contains_wheel_audit_finding_summary() {
        let notification = WheelAuditFindingNotification {
            tenant_slug: "acme".into(),
            project_name: "demo".into(),
            version: "1.0.0".into(),
            wheel_filename: "demo-1.0.0-py3-none-any.whl".into(),
            scanned_file_count: 12,
            source_security_scan_error: None,
            virus_scan_error: Some("rules unavailable".into()),
            findings: vec![WheelAuditFinding {
                kind: WheelAuditFindingKind::PostInstallClue,
                path: Some("demo.pth".into()),
                summary: "package contents include post-install or startup behavior clues".into(),
                evidence: vec!["`.pth` file executes import-time code".into()],
            }],
        };

        let payload =
            DiscordWebhookPayload::for_wheel_audit_findings(&notification, Some("Pyregistry"));
        let json = serde_json::to_value(payload).expect("payload json");

        assert_eq!(json["username"], "Pyregistry");
        assert_eq!(
            json["content"],
            "Wheel security findings detected: `acme/demo 1.0.0` `demo-1.0.0-py3-none-any.whl`"
        );
        assert_eq!(json["allowed_mentions"]["parse"], Value::Array(Vec::new()));
        assert_eq!(
            json["embeds"][0]["title"],
            "Wheel security findings detected"
        );
        assert_eq!(json["embeds"][0]["color"], 0xe67e22);
        assert!(
            json["embeds"][0]["fields"]
                .as_array()
                .is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|field| field["name"] == "Findings" && field["value"] == "1")
                        && fields.iter().any(|field| {
                            field["name"] == "Finding summary"
                                && field["value"].as_str().is_some_and(|value| {
                                    value.contains("PostInstallClue") && value.contains("demo.pth")
                                })
                        })
                })
        );
    }

    #[test]
    fn discord_payload_contains_package_publish_summary() {
        let notification = PackagePublishNotification {
            kind: PackagePublishEventKind::NewVersion,
            tenant_slug: "acme".into(),
            project_name: "Demo_Pkg".into(),
            normalized_name: "demo-pkg".into(),
            version: "1.1.0".into(),
            filename: "demo-pkg-1.1.0-py3-none-any.whl".into(),
            size_bytes: 42,
            sha256: "abc123".into(),
        };

        let payload = DiscordWebhookPayload::for_package_publish(&notification, Some("Pyregistry"));
        let json = serde_json::to_value(payload).expect("payload json");

        assert_eq!(json["username"], "Pyregistry");
        assert_eq!(
            json["content"],
            "New package version published: `acme/Demo_Pkg 1.1.0`"
        );
        assert_eq!(json["allowed_mentions"]["parse"], Value::Array(Vec::new()));
        assert_eq!(json["embeds"][0]["title"], "New package version published");
        assert_eq!(json["embeds"][0]["color"], 0x3498db);
        assert!(
            json["embeds"][0]["fields"]
                .as_array()
                .is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|field| field["name"] == "Version" && field["value"] == "1.1.0")
                        && fields.iter().any(|field| {
                            field["name"] == "File"
                                && field["value"] == "demo-pkg-1.1.0-py3-none-any.whl"
                        })
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
