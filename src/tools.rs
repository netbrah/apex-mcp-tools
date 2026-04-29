use anyhow::{Result, bail};
use serde_json::{json, Value};

use crate::client::BlackDuckClient;

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

pub fn list_tools() -> Vec<Value> {
    vec![
        // -- Discovery --
        tool_def(
            "bd_server_info",
            "Get BlackDuck Hub server version and status",
            json!({"type": "object", "properties": {}}),
        ),
        tool_def(
            "bd_list_projects",
            "List projects. Optional: q (search query), limit, offset",
            json!({
                "type": "object",
                "properties": {
                    "q": {"type": "string", "description": "Search query, e.g. 'name:ONTAP'"},
                    "limit": {"type": "integer", "description": "Max results (default 25)"},
                    "offset": {"type": "integer", "description": "Pagination offset"}
                }
            }),
        ),
        tool_def(
            "bd_get_project",
            "Get a single project by ID (UUID from project href)",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Project UUID"}
                },
                "required": ["project_id"]
            }),
        ),
        tool_def(
            "bd_list_versions",
            "List versions for a project",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "description": "Project UUID"},
                    "q": {"type": "string", "description": "Search query for version name"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"}
                },
                "required": ["project_id"]
            }),
        ),

        // -- BOM / Components --
        tool_def(
            "bd_list_bom_components",
            "List BOM components for a project version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),
        tool_def(
            "bd_get_component_detail",
            "Get details of a specific component in the BOM including licenses and origins",
            json!({
                "type": "object",
                "properties": {
                    "component_href": {"type": "string", "description": "Full component href URL"}
                },
                "required": ["component_href"]
            }),
        ),

        // -- Vulnerabilities --
        tool_def(
            "bd_list_vulnerabilities",
            "List vulnerable BOM components for a project version. Returns CVE details, severity, remediation status.",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),
        tool_def(
            "bd_get_vulnerability_detail",
            "Get detailed CVE/BDSA information for a specific vulnerability by ID",
            json!({
                "type": "object",
                "properties": {
                    "vuln_id": {"type": "string", "description": "CVE or BDSA ID, e.g. CVE-2023-12345"}
                },
                "required": ["vuln_id"]
            }),
        ),
        tool_def(
            "bd_get_risk_profile",
            "Get risk profile summary (vuln counts by severity, license risk, operational risk) for a version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),

        // -- Policy / Compliance --
        tool_def(
            "bd_get_policy_status",
            "Get policy compliance status for a project version — violations, overrides, clean components",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),
        tool_def(
            "bd_list_policy_rules",
            "List active policy rules applied to a project version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),

        // -- License Compliance --
        tool_def(
            "bd_list_license_reports",
            "List available license/notice report types for a project version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),

        // -- Code Locations / Scans --
        tool_def(
            "bd_list_codelocations",
            "List scan/code locations for a project version — shows what was scanned and when",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),

        // -- Compliance Dashboard --
        tool_def(
            "bd_compliance_summary",
            "One-shot compliance dashboard: policy status, vuln counts by severity, license risk, BOM size, and scan freshness for a project version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),
        tool_def(
            "bd_search_vulnerabilities_by_severity",
            "Search vulnerable components filtered by severity (CRITICAL, HIGH, MEDIUM, LOW)",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "limit": {"type": "integer"}
                },
                "required": ["project_id", "version_id", "severity"]
            }),
        ),
        tool_def(
            "bd_get_bom_status",
            "Get BOM completion/scan status for a project version",
            json!({
                "type": "object",
                "properties": {
                    "project_id": {"type": "string"},
                    "version_id": {"type": "string"}
                },
                "required": ["project_id", "version_id"]
            }),
        ),
    ]
}

fn tool_def(name: &str, desc: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": schema
    })
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

pub async fn call_tool(name: &str, args: Value, bd: &BlackDuckClient) -> Result<String> {
    match name {
        "bd_server_info" => server_info(bd).await,
        "bd_list_projects" => list_projects(args, bd).await,
        "bd_get_project" => get_project(args, bd).await,
        "bd_list_versions" => list_versions(args, bd).await,
        "bd_list_bom_components" => list_bom_components(args, bd).await,
        "bd_get_component_detail" => get_component_detail(args, bd).await,
        "bd_list_vulnerabilities" => list_vulnerabilities(args, bd).await,
        "bd_get_vulnerability_detail" => get_vulnerability_detail(args, bd).await,
        "bd_get_risk_profile" => get_risk_profile(args, bd).await,
        "bd_get_policy_status" => get_policy_status(args, bd).await,
        "bd_list_policy_rules" => list_policy_rules(args, bd).await,
        "bd_list_license_reports" => list_license_reports(args, bd).await,
        "bd_list_codelocations" => list_codelocations(args, bd).await,
        "bd_compliance_summary" => compliance_summary(args, bd).await,
        "bd_search_vulnerabilities_by_severity" => search_vulns_by_severity(args, bd).await,
        "bd_get_bom_status" => get_bom_status(args, bd).await,
        _ => bail!("Unknown tool: {name}"),
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn str_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn int_arg(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key)
        .and_then(|v| v.as_i64())
        .unwrap_or(default)
}

fn version_base(bd: &BlackDuckClient, project_id: &str, version_id: &str) -> String {
    format!(
        "{}/api/projects/{}/versions/{}",
        bd.base_url(),
        project_id,
        version_id
    )
}

fn paginate(args: &Value) -> String {
    let limit = int_arg(args, "limit", 25);
    let offset = int_arg(args, "offset", 0);
    format!("limit={limit}&offset={offset}")
}

fn format_json(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

// Extract link hrefs from _meta.links by rel name
fn find_link(item: &Value, rel: &str) -> Option<String> {
    item.get("_meta")
        .and_then(|m| m.get("links"))
        .and_then(|links| links.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|l| l.get("rel").and_then(|r| r.as_str()) == Some(rel))
                .and_then(|l| l.get("href").and_then(|h| h.as_str()))
                .map(|s| s.to_string())
        })
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async fn server_info(bd: &BlackDuckClient) -> Result<String> {
    let v = bd.get("/api/current-version").await?;
    Ok(format_json(&v))
}

async fn list_projects(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pag = paginate(&args);
    let q = str_arg(&args, "q").map(|q| format!("&q={q}")).unwrap_or_default();
    let data = bd.get(&format!("/api/projects?{pag}{q}")).await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("Total projects: {total}\n\n");
    if let Some(items) = items {
        for p in items {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let href = p.get("_meta")
                .and_then(|m| m.get("href"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Extract UUID from href
            let id = href.rsplit('/').next().unwrap_or("?");
            let created = p.get("createdAt").and_then(|v| v.as_str()).unwrap_or("?");
            out.push_str(&format!("- {name}\n  ID: {id}\n  Created: {created}\n\n"));
        }
    }
    Ok(out)
}

async fn get_project(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let data = bd.get(&format!("/api/projects/{pid}")).await?;
    Ok(format_json(&data))
}

async fn list_versions(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let pag = paginate(&args);
    let q = str_arg(&args, "q").map(|q| format!("&q={q}")).unwrap_or_default();
    let data = bd
        .get(&format!("/api/projects/{pid}/versions?{pag}{q}"))
        .await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("Total versions: {total}\n\n");
    if let Some(items) = items {
        for v in items {
            let name = v.get("versionName").and_then(|v| v.as_str()).unwrap_or("?");
            let phase = v.get("phase").and_then(|v| v.as_str()).unwrap_or("?");
            let href = v.get("_meta").and_then(|m| m.get("href")).and_then(|v| v.as_str()).unwrap_or("");
            let id = href.rsplit('/').next().unwrap_or("?");
            out.push_str(&format!("- {name} [{phase}]\n  ID: {id}\n\n"));
        }
    }
    Ok(out)
}

async fn list_bom_components(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let pag = paginate(&args);
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/components?{pag}")).await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("BOM Components: {total}\n\n");
    if let Some(items) = items {
        for c in items {
            let name = c.get("componentName").and_then(|v| v.as_str()).unwrap_or("?");
            let ver = c.get("componentVersionName").and_then(|v| v.as_str()).unwrap_or("?");
            let policy = c.get("policyStatus").and_then(|v| v.as_str()).unwrap_or("?");
            let review = c.get("reviewStatus").and_then(|v| v.as_str()).unwrap_or("?");
            let match_types: Vec<&str> = c.get("matchTypes")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let href = c.get("_meta").and_then(|m| m.get("href")).and_then(|v| v.as_str()).unwrap_or("");

            out.push_str(&format!(
                "- {name} {ver}\n  Policy: {policy} | Review: {review} | Match: {}\n  href: {href}\n\n",
                match_types.join(", ")
            ));
        }
    }
    Ok(out)
}

async fn get_component_detail(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let href = str_arg(&args, "component_href").ok_or_else(|| anyhow::anyhow!("component_href required"))?;
    let data = bd.get(&href).await?;
    Ok(format_json(&data))
}

async fn list_vulnerabilities(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let pag = paginate(&args);
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/vulnerable-bom-components?{pag}")).await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("Vulnerable Components: {total}\n\n");
    if let Some(items) = items {
        for c in items {
            let comp = c.get("componentName").and_then(|v| v.as_str()).unwrap_or("?");
            let ver = c.get("componentVersionName").and_then(|v| v.as_str()).unwrap_or("?");
            let vwr = c.get("vulnerabilityWithRemediation");
            let vuln_name = vwr.and_then(|v| v.get("vulnerabilityName")).and_then(|v| v.as_str()).unwrap_or("?");
            let severity = vwr.and_then(|v| v.get("severity")).and_then(|v| v.as_str()).unwrap_or("?");
            let score = vwr.and_then(|v| v.get("overallScore")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let status = vwr.and_then(|v| v.get("remediationStatus")).and_then(|v| v.as_str()).unwrap_or("?");
            let desc = vwr.and_then(|v| v.get("description")).and_then(|v| v.as_str()).unwrap_or("");
            let desc_short = if desc.len() > 120 { &desc[..120] } else { desc };

            out.push_str(&format!(
                "- {vuln_name} ({severity}, CVSS {score:.1})\n  Component: {comp} {ver}\n  Remediation: {status}\n  {desc_short}\n\n"
            ));
        }
    }
    Ok(out)
}

async fn get_vulnerability_detail(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let vuln_id = str_arg(&args, "vuln_id").ok_or_else(|| anyhow::anyhow!("vuln_id required"))?;
    // Try CVE first, then BDSA
    let path = if vuln_id.starts_with("BDSA") {
        format!("/api/vulnerabilities/{vuln_id}")
    } else {
        format!("/api/vulnerabilities/{vuln_id}")
    };
    let data = bd.get(&path).await?;
    Ok(format_json(&data))
}

async fn get_risk_profile(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/risk-profile")).await?;

    let mut out = String::from("Risk Profile\n============\n\n");

    for category in &["categories"] {
        if let Some(cats) = data.get(category).and_then(|v| v.as_object()) {
            for (cat_name, counts) in cats {
                out.push_str(&format!("{cat_name}:\n"));
                if let Some(counts) = counts.as_object() {
                    for (level, count) in counts {
                        out.push_str(&format!("  {level}: {count}\n"));
                    }
                }
                out.push('\n');
            }
        }
    }
    Ok(out)
}

async fn get_policy_status(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/policy-status")).await?;

    let overall = data.get("overallStatus").and_then(|v| v.as_str()).unwrap_or("?");
    let updated = data.get("updatedAt").and_then(|v| v.as_str()).unwrap_or("?");

    let mut out = format!("Policy Status: {overall}\nLast Updated: {updated}\n\n");

    if let Some(counts) = data.get("componentVersionStatusCounts").and_then(|v| v.as_array()) {
        out.push_str("Component Status Counts:\n");
        for c in counts {
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let val = c.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
            let icon = match name {
                "IN_VIOLATION" => "X",
                "IN_VIOLATION_OVERRIDDEN" => "!",
                "NOT_IN_VIOLATION" => "OK",
                _ => "-",
            };
            out.push_str(&format!("  [{icon}] {name}: {val}\n"));
        }
    }
    Ok(out)
}

async fn list_policy_rules(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/active-policy-rules")).await?;
    Ok(format_json(&data))
}

async fn list_license_reports(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/licenseReports")).await?;
    Ok(format_json(&data))
}

async fn list_codelocations(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let pag = paginate(&args);
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/codelocations?{pag}")).await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("Code Locations: {total}\n\n");
    if let Some(items) = items {
        for loc in items {
            let name = loc.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let scan_type = loc.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            let updated = loc.get("updatedAt").and_then(|v| v.as_str()).unwrap_or("?");
            let url = loc.get("url").and_then(|v| v.as_str()).unwrap_or("");
            out.push_str(&format!(
                "- {name}\n  Type: {scan_type} | Updated: {updated}\n  URL: {url}\n\n"
            ));
        }
    }
    Ok(out)
}

async fn compliance_summary(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);

    // Fetch all three in parallel
    let url_policy = format!("{base}/policy-status");
    let url_risk = format!("{base}/risk-profile");
    let url_bom = format!("{base}/components?limit=1");
    let url_vuln = format!("{base}/vulnerable-bom-components?limit=1");
    let (version_data, policy_data, risk_data, bom_data, vuln_data) = tokio::join!(
        bd.get(&base),
        bd.get(&url_policy),
        bd.get(&url_risk),
        bd.get(&url_bom),
        bd.get(&url_vuln),
    );

    let mut out = String::from("=== COMPLIANCE DASHBOARD ===\n\n");

    // Version info
    if let Ok(v) = &version_data {
        let name = v.get("versionName").and_then(|v| v.as_str()).unwrap_or("?");
        let phase = v.get("phase").and_then(|v| v.as_str()).unwrap_or("?");
        let dist = v.get("distribution").and_then(|v| v.as_str()).unwrap_or("?");
        out.push_str(&format!("Version: {name} [{phase}] Distribution: {dist}\n\n"));
    }

    // Policy
    out.push_str("--- POLICY ---\n");
    if let Ok(p) = &policy_data {
        let status = p.get("overallStatus").and_then(|v| v.as_str()).unwrap_or("?");
        let icon = if status == "NOT_IN_VIOLATION" { "PASS" } else { "FAIL" };
        out.push_str(&format!("[{icon}] {status}\n"));
        if let Some(counts) = p.get("componentVersionStatusCounts").and_then(|v| v.as_array()) {
            for c in counts {
                let n = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let val = c.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
                if val > 0 || n == "IN_VIOLATION" {
                    out.push_str(&format!("  {n}: {val}\n"));
                }
            }
        }
    } else {
        out.push_str("  (unavailable)\n");
    }

    // BOM size
    out.push_str("\n--- BOM ---\n");
    if let Ok(b) = &bom_data {
        let total = b.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
        out.push_str(&format!("Total components: {total}\n"));
    }

    // Vulnerabilities count
    out.push_str("\n--- VULNERABILITIES ---\n");
    if let Ok(v) = &vuln_data {
        let total = v.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
        out.push_str(&format!("Total vulnerable components: {total}\n"));
    }

    // Risk profile
    out.push_str("\n--- RISK PROFILE ---\n");
    if let Ok(r) = &risk_data {
        if let Some(cats) = r.get("categories").and_then(|v| v.as_object()) {
            for (cat, counts) in cats {
                out.push_str(&format!("{cat}: "));
                if let Some(obj) = counts.as_object() {
                    let parts: Vec<String> = obj
                        .iter()
                        .filter(|(_, v)| v.as_i64().unwrap_or(0) > 0)
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    if parts.is_empty() {
                        out.push_str("clean");
                    } else {
                        out.push_str(&parts.join(", "));
                    }
                }
                out.push('\n');
            }
        }
    }

    out.push_str("\n=== END DASHBOARD ===\n");
    Ok(out)
}

async fn search_vulns_by_severity(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let severity = str_arg(&args, "severity").ok_or_else(|| anyhow::anyhow!("severity required"))?;
    let limit = int_arg(&args, "limit", 25);
    let base = version_base(bd, &pid, &vid);

    // Hub supports filter query params
    let data = bd
        .get(&format!(
            "{base}/vulnerable-bom-components?limit={limit}&filter=vulnerabilityWithRemediation.severity:{severity}"
        ))
        .await?;

    let total = data.get("totalCount").and_then(|v| v.as_i64()).unwrap_or(0);
    let items = data.get("items").and_then(|v| v.as_array());

    let mut out = format!("{severity} Vulnerabilities: {total}\n\n");
    if let Some(items) = items {
        for c in items {
            let comp = c.get("componentName").and_then(|v| v.as_str()).unwrap_or("?");
            let ver = c.get("componentVersionName").and_then(|v| v.as_str()).unwrap_or("?");
            let vwr = c.get("vulnerabilityWithRemediation");
            let vuln = vwr.and_then(|v| v.get("vulnerabilityName")).and_then(|v| v.as_str()).unwrap_or("?");
            let score = vwr.and_then(|v| v.get("overallScore")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            out.push_str(&format!("- {vuln} (CVSS {score:.1}) in {comp} {ver}\n"));
        }
    }
    Ok(out)
}

async fn get_bom_status(args: Value, bd: &BlackDuckClient) -> Result<String> {
    let pid = str_arg(&args, "project_id").ok_or_else(|| anyhow::anyhow!("project_id required"))?;
    let vid = str_arg(&args, "version_id").ok_or_else(|| anyhow::anyhow!("version_id required"))?;
    let base = version_base(bd, &pid, &vid);
    let data = bd.get(&format!("{base}/bom-status")).await?;
    Ok(format_json(&data))
}
