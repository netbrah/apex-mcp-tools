use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::BlackDuckClient;
use crate::tools;

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

fn ok_response(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

fn err_response(id: Option<Value>, code: i64, msg: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(json!({"code": code, "message": msg})),
    }
}

pub async fn handle_message(raw: &str, bd: &BlackDuckClient) -> JsonRpcResponse {
    let req: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => return err_response(None, -32700, &format!("Parse error: {e}")),
    };

    if req.jsonrpc != "2.0" {
        return err_response(req.id, -32600, "Invalid jsonrpc version");
    }

    match req.method.as_str() {
        "initialize" => ok_response(
            req.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": { "listChanged": false }
                },
                "serverInfo": {
                    "name": "blackduck-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),

        "notifications/initialized" => {
            // No response needed for notifications, but we return empty
            ok_response(req.id, json!({}))
        }

        "tools/list" => {
            let tool_list = tools::list_tools();
            ok_response(req.id, json!({ "tools": tool_list }))
        }

        "tools/call" => {
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            match tools::call_tool(name, args, bd).await {
                Ok(result) => ok_response(
                    req.id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": result
                        }]
                    }),
                ),
                Err(e) => ok_response(
                    req.id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("Error: {e}")
                        }],
                        "isError": true
                    }),
                ),
            }
        }

        _ => err_response(req.id, -32601, &format!("Method not found: {}", req.method)),
    }
}
