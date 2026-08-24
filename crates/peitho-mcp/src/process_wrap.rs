//! Real OS process wrapper and stdio stream pipe for Model Context Protocol servers.

use std::process::Stdio;
use std::sync::Arc;
use peitho_token::{CapabilityToken, RevocationRegistry};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::McpError;
use crate::interceptor::{InterceptDecision, McpInterceptor};
use crate::protocol::JsonRpcRequest;

/// A production OS process wrapper intercepting live stdio MCP traffic.
pub struct ProcessShield {
    interceptor: McpInterceptor,
}

impl ProcessShield {
    /// Create a new process shield with optional revocation registry.
    pub fn new(revocation_registry: Option<Arc<RevocationRegistry>>) -> Self {
        let interceptor = match revocation_registry {
            Some(registry) => McpInterceptor::with_revocation(registry),
            None => McpInterceptor::new(),
        };
        Self { interceptor }
    }

    /// Spawn a target child MCP process and transparently shield its stdio streams.
    pub async fn run_shielded_process(
        &self,
        command_str: &str,
        active_token: Option<CapabilityToken>,
    ) -> Result<i32, McpError> {
        let parts: Vec<&str> = command_str.split_whitespace().collect();
        let program = match parts.first() {
            Some(p) => *p,
            None => return Err(McpError::ProtocolError("empty command string".to_string())),
        };
        let args = parts.get(1..).unwrap_or(&[]);

        info!("🛡️ [Peitho MCP Shield] Spawning protected child process: {}", command_str);

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(McpError::Io)?;

        let child_stdin = child.stdin.take().ok_or_else(|| {
            McpError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "cannot open child stdin"))
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            McpError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "cannot open child stdout"))
        })?;

        let mut parent_stdin_reader = BufReader::new(tokio::io::stdin()).lines();
        let mut parent_stdout = tokio::io::stdout();
        let mut child_stdout_reader = BufReader::new(child_stdout).lines();
        let mut child_stdin_writer = child_stdin;

        // Forward child stdout to parent stdout asynchronously
        let stdout_forwarder = tokio::spawn(async move {
            while let Ok(Some(line)) = child_stdout_reader.next_line().await {
                let formatted = format!("{}\n", line);
                let _ = parent_stdout.write_all(formatted.as_bytes()).await;
                let _ = parent_stdout.flush().await;
            }
        });

        // Intercept parent stdin -> child stdin
        while let Ok(Some(line)) = parent_stdin_reader.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(request) => {
                    match self.interceptor.evaluate(&request, active_token.as_ref())? {
                        InterceptDecision::Allow => {
                            let formatted = format!("{}\n", line);
                            if let Err(e) = child_stdin_writer.write_all(formatted.as_bytes()).await {
                                warn!("Child process stdin write failed: {}", e);
                                break;
                            }
                            let _ = child_stdin_writer.flush().await;
                        }
                        InterceptDecision::Deny(deny_resp) => {
                            let err_json = serde_json::to_string(&deny_resp)
                                .unwrap_or_else(|_| "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Blocked\"}}".to_string());
                            let mut out = tokio::io::stdout();
                            let _ = out.write_all(format!("{}\n", err_json).as_bytes()).await;
                            let _ = out.flush().await;
                        }
                    }
                }
                Err(e) => {
                    warn!("Unrecognized JSON-RPC line: {}", e);
                    let _ = child_stdin_writer.write_all(format!("{}\n", line).as_bytes()).await;
                    let _ = child_stdin_writer.flush().await;
                }
            }
        }

        let _ = stdout_forwarder.await;
        let status = child.wait().await.map_err(McpError::Io)?;
        Ok(status.code().unwrap_or(0))
    }
}
