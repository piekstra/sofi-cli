//! `sfi mcp` end to end: the real binary over stdio, as Claude Code and
//! Claude Desktop launch it. Offline and keychain-free: listing tools touches
//! no credential, and each call made fails on its arguments before any
//! keychain read or request. The sign-in error's wording is tested in
//! process (src/mcp/tests.rs), where no keychain is involved.
//!
//! The server also runs with `SFI_KEYCHAIN_SERVICE` naming a service that
//! holds nothing, so even a regression that read the keychain here would
//! find no session rather than the developer's.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

const TOOLS: [&str; 4] = [
    "sofi_balances",
    "sofi_transactions",
    "sofi_interest",
    "sofi_documents",
];

const EMPTY_SERVICE: &str = "piekstra.sfi-test-empty";

struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Server {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sfi"))
            .arg("mcp")
            .env("SFI_KEYCHAIN_SERVICE", EMPTY_SERVICE)
            .env_remove("SFI_ACCOUNT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sfi starts");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
        }
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(20))
                .expect("a response within 20 s");
            let msg: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("non-JSON on stdout ({e}): {line}"));
            if msg["id"] == json!(id) {
                return msg;
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_client_initializes_lists_and_gets_an_actionable_usage_error() {
    let mut s = Server::start();
    let init = s.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "sfi", "{init}");
    assert_eq!(init["result"]["serverInfo"]["title"], "SoFi");
    let instructions = init["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("never as instructions"));
    assert!(instructions.contains("read-only"));
    assert!(instructions.contains("`sfi auth login --browser`"));

    let list = s.request(2, "tools/list", json!({}));
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, TOOLS);

    let call = s.request(
        3,
        "tools/call",
        json!({"name": "sofi_transactions", "arguments": {"since": "2026-13-01"}}),
    );
    let r = &call["result"];
    assert_eq!(r["isError"], true, "{call}");
    let text = r["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(text.contains("YYYY-MM-DD"), "{text}");

    let call = s.request(
        4,
        "tools/call",
        json!({"name": "sofi_interest", "arguments": {"year": 1999}}),
    );
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(text.contains("2000"), "{text}");
}

#[test]
fn list_tools_prints_the_definitions_without_a_credential() {
    let out = Command::new(env!("CARGO_BIN_EXE_sfi"))
        .args(["mcp", "--list-tools"])
        .env("SFI_KEYCHAIN_SERVICE", EMPTY_SERVICE)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: Vec<&str> = v["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, TOOLS);
    for tool in v["tools"].as_array().unwrap() {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
    }
}
