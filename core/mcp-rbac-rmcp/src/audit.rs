//! Synchronous decision ledger. Each append locks the SQLite writer, reads the chain head,
//! and commits before dispatch. The resulting table is verifiable by mcp-rbac audit-verify.
use crate::DecisionEvent;
use mcp_rbac_core::json::canonical;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};

pub struct AuditSink(Mutex<Connection>);

#[derive(Clone, Copy)]
pub enum ExportBody {
    /// Export chain links and row id, keeping the stored event local.
    LinksOnly,
    /// Include the hashed event, including the subject and tenant.
    FullEvent,
}

pub struct CommittedRow {
    pub id: i64,
    pub event: String,
    pub prev: String,
    pub hash: String,
}

impl AuditSink {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL,
            sub TEXT, tool TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, tenant TEXT, rule TEXT,
            approved INTEGER, duration_ms REAL, event TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)")?;
        Ok(Self(Mutex::new(db)))
    }

    pub fn write(&self, e: &DecisionEvent) -> rusqlite::Result<CommittedRow> {
        let d = &e.decision;
        let sub = e.identity.as_ref().and_then(|id| id["id"].as_str());
        let tenant = d["tenant"].as_str();
        let rule = d["rule"].as_str();
        let ms = (e.duration.as_secs_f64() * 1e6).round() / 1000.;
        let mut fields = json!({"tool":e.tool,"decision":d["decision"],"reason":d["reason"],
            "approved":e.approved,"durationMs":ms});
        for (key, value) in [("sub", sub), ("rule", rule), ("tenant", tenant)] {
            if let Some(value) = value {
                fields[key] = Value::String(value.to_owned());
            }
        }
        self.append(fields)
    }

    pub(crate) fn write_feedback(
        &self,
        e: &crate::FeedbackEvent,
    ) -> rusqlite::Result<CommittedRow> {
        self.append(e.audit_event("", e.identity["id"].as_str()))
    }

    fn append(&self, mut fields: Value) -> rusqlite::Result<CommittedRow> {
        let mut db = self.0.lock().unwrap_or_else(|err| err.into_inner());
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prev = tx
            .query_row("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let at: String = tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |r| {
            r.get(0)
        })?;
        fields["at"] = json!(at);
        let event = canonical(&fields);
        fields["prev"] = Value::String(prev.clone());
        let hash = Sha256::digest(format!("{prev}\n{}", canonical(&fields)))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        tx.execute("INSERT INTO audit(at,sub,tool,decision,reason,tenant,rule,approved,duration_ms,event,prev,hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", params![at,fields["sub"].as_str(),fields["tool"].as_str(),fields["decision"].as_str(),fields["reason"].as_str(),
            fields["tenant"].as_str(),fields["rule"].as_str(),fields["approved"].as_bool(),fields["durationMs"].as_f64(),event,prev,hash])?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(CommittedRow {
            id,
            event,
            prev,
            hash,
        })
    }
}
