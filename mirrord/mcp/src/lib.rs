mod error;

use std::{future::Future, pin::Pin};

use mcp_core::{
    handler::{PromptError, ResourceError},
    prompt::Prompt,
    protocol::{JsonRpcMessage, ServerCapabilities, ToolsCapability},
    tool::{Tool, ToolAnnotations},
    Annotations, Content, Resource, Role, TextContent, ToolError,
};
use mcp_server::{
    router::{Router, RouterService},
    ByteTransport, Server,
};
use serde_json::Value;
use tokio::{
    io::{stdin, stdout},
    sync::mpsc::Sender,
};

pub use crate::error::McpError;

// A simple counter service that demonstrates the Router trait
#[derive(Clone)]
struct MirrordRouter;

impl MirrordRouter {
    fn config_schema(&self) -> Result<Vec<Content>, ToolError> {
        let config_schema = schemars::schema_for!(mirrord_config::LayerFileConfig);
        let config_schema =
            serde_json::to_string_pretty(&config_schema).expect("Failed generating schema!");
        let content = Content::Text(TextContent {
            text: config_schema,
            annotations: Some(Annotations {
                audience: Some(vec![Role::Assistant]),
                priority: None,
                timestamp: None,
            }),
        });

        Ok(vec![content])
    }
}

impl Router for MirrordRouter {
    fn name(&self) -> String {
        "mirrord".to_string()
    }

    fn instructions(&self) -> String {
        r#"This server provides tools that are based on mirrord. 
It allows you to use the following tools:
* 'config-schema' to retrieve JSONSchema of the mirrord configuration. can be useful when creating/editing mirrord configuration files."#
            .to_string()
    }

    fn capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            prompts: None,
            resources: None,
            tools: Some(ToolsCapability {
                list_changed: Some(false),
            }),
        }
    }

    fn list_tools(&self) -> Vec<Tool> {
        vec![Tool::new(
            "config-schema".to_string(),
            "Retrieve JSONSchema of the mirrord configuration. can be useful when creating/editing mirrord configuration files. Note deployment/rollout needs to be inside path field".to_string(),
            serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            Some(ToolAnnotations {
                title: Some("Config Schema Tool".to_string()),
                read_only_hint: true,
                destructive_hint: false,
                idempotent_hint: false,
                open_world_hint: false,
            }),
        )]
    }

    fn call_tool(
        &self,
        tool_name: &str,
        _arguments: Value,
        _notifier: Sender<JsonRpcMessage>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Content>, ToolError>> + Send + 'static>> {
        let this = self.clone();
        let tool_name = tool_name.to_string();
        Box::pin(async move {
            match tool_name.as_str() {
                "config-schema" => this.config_schema(),
                _ => Err(ToolError::NotFound(format!("Tool {tool_name} not found"))),
            }
        })
    }

    fn list_resources(&self) -> Vec<Resource> {
        vec![]
    }

    fn read_resource(
        &self,
        uri: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, ResourceError>> + Send + 'static>> {
        let uri = uri.to_string();
        Box::pin(async move {
            Err(ResourceError::NotFound(
                format!("Resource {uri} not found",),
            ))
        })
    }

    fn list_prompts(&self) -> Vec<Prompt> {
        vec![]
    }

    fn get_prompt(
        &self,
        prompt_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<String, PromptError>> + Send + 'static>> {
        let prompt_id = prompt_id.to_string();
        Box::pin(async move {
            Err(PromptError::NotFound(format!(
                "Prompt {prompt_id} not found"
            )))
        })
    }
}

pub async fn start_mcp_server() -> Result<(), McpError> {
    tracing::info!("Starting MCP server");

    // Create an instance of our counter router
    let router = RouterService(MirrordRouter);

    // Create and run the server
    let server = Server::new(router);
    let transport = ByteTransport::new(stdin(), stdout());

    tracing::info!("Server initialized and ready to handle requests");
    server.run(transport).await?;
    Ok(())
}
