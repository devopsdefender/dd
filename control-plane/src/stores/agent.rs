use chrono::Utc;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Agent record as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub id: String,
    pub vm_name: String,
    pub status: String,
    pub registration_state: String,
    pub hostname: Option<String>,
    pub tunnel_id: Option<String>,
    pub mrtd: Option<String>,
    pub tcb_status: Option<String>,
    pub node_size: Option<String>,
    pub datacenter: Option<String>,
    pub github_owner: Option<String>,
    pub deployment_id: Option<String>,
    pub created_at: String,
    pub last_heartbeat_at: Option<String>,
}

fn row_to_agent(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentRow> {
    Ok(AgentRow {
        id: row.get("id")?,
        vm_name: row.get("vm_name")?,
        status: row.get("status")?,
        registration_state: row.get("registration_state")?,
        hostname: row.get("hostname")?,
        tunnel_id: row.get("tunnel_id")?,
        mrtd: row.get("mrtd")?,
        tcb_status: row.get("tcb_status")?,
        node_size: row.get("node_size")?,
        datacenter: row.get("datacenter")?,
        github_owner: row.get("github_owner")?,
        deployment_id: row.get("deployment_id")?,
        created_at: row.get("created_at")?,
        last_heartbeat_at: row.get("last_heartbeat_at")?,
    })
}

/// Insert a new agent record.
pub fn insert_agent(db: &Db, agent: &AgentRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO agents (id, vm_name, status, registration_state, hostname, tunnel_id, \
         mrtd, tcb_status, node_size, datacenter, github_owner, deployment_id, created_at, \
         last_heartbeat_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            agent.id,
            agent.vm_name,
            agent.status,
            agent.registration_state,
            agent.hostname,
            agent.tunnel_id,
            agent.mrtd,
            agent.tcb_status,
            agent.node_size,
            agent.datacenter,
            agent.github_owner,
            agent.deployment_id,
            agent.created_at,
            agent.last_heartbeat_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

/// Get an agent by ID.
pub fn get_agent(db: &Db, id: &str) -> AppResult<Option<AgentRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, vm_name, status, registration_state, hostname, tunnel_id, \
             mrtd, tcb_status, node_size, datacenter, github_owner, deployment_id, created_at, \
             last_heartbeat_at FROM agents WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![id], row_to_agent)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// Find an agent by VM name (most recent first).
pub fn find_agent_by_vm_name(db: &Db, vm_name: &str) -> AppResult<Option<AgentRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, vm_name, status, registration_state, hostname, tunnel_id, \
             mrtd, tcb_status, node_size, datacenter, github_owner, deployment_id, created_at, \
             last_heartbeat_at FROM agents WHERE vm_name = ?1 ORDER BY created_at DESC LIMIT 1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![vm_name], row_to_agent)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// List all agents.
pub fn list_agents(db: &Db) -> AppResult<Vec<AgentRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, vm_name, status, registration_state, hostname, tunnel_id, \
             mrtd, tcb_status, node_size, datacenter, github_owner, deployment_id, created_at, \
             last_heartbeat_at FROM agents ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map([], row_to_agent)
        .map_err(|_| AppError::Internal)?;

    let mut agents = Vec::new();
    for row in rows {
        agents.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(agents)
}

/// Delete an agent by ID.
pub fn delete_agent(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute("DELETE FROM agents WHERE id = ?1", params![id])
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Update agent status.
pub fn update_agent_status(db: &Db, id: &str, status: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE agents SET status = ?1 WHERE id = ?2",
            params![status, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Assign or clear the deployment currently associated with an agent.
pub fn update_agent_deployment(db: &Db, id: &str, deployment_id: Option<&str>) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE agents SET deployment_id = ?1 WHERE id = ?2",
            params![deployment_id, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Update agent registration state.
pub fn update_registration_state(db: &Db, id: &str, state: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE agents SET registration_state = ?1 WHERE id = ?2",
            params![state, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Update agent heartbeat timestamp.
pub fn update_heartbeat(db: &Db, id: &str) -> AppResult<bool> {
    let now = Utc::now().to_rfc3339();
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE agents SET last_heartbeat_at = ?1 WHERE id = ?2",
            params![now, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Find an undeployed agent, optionally filtering by node_size and datacenter.
pub fn find_available_agent(
    db: &Db,
    node_size: Option<&str>,
    datacenter: Option<&str>,
) -> AppResult<Option<AgentRow>> {
    let conn = db.lock().unwrap();
    let mut query = String::from(
        "SELECT id, vm_name, status, registration_state, hostname, tunnel_id, \
         mrtd, tcb_status, node_size, datacenter, github_owner, deployment_id, created_at, \
         last_heartbeat_at FROM agents WHERE status = 'undeployed' AND registration_state = 'ready' \
         AND deployment_id IS NULL",
    );
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ns) = node_size {
        bind_values.push(ns.to_string());
        query.push_str(&format!(" AND node_size = ?{}", bind_values.len()));
    }
    if let Some(dc) = datacenter {
        bind_values.push(dc.to_string());
        query.push_str(&format!(" AND datacenter = ?{}", bind_values.len()));
    }
    query.push_str(" LIMIT 1");

    let mut stmt = conn.prepare(&query).map_err(|_| AppError::Internal)?;

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = bind_values
        .iter()
        .map(|s| s as &dyn rusqlite::types::ToSql)
        .collect();

    let result = stmt
        .query_row(param_refs.as_slice(), row_to_agent)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

// We need this trait extension for optional query results
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    fn make_agent(id: &str, vm_name: &str) -> AgentRow {
        AgentRow {
            id: id.into(),
            vm_name: vm_name.into(),
            status: "undeployed".into(),
            registration_state: "ready".into(),
            hostname: Some("test.devopsdefender.com".into()),
            tunnel_id: None,
            mrtd: None,
            tcb_status: None,
            node_size: None,
            datacenter: None,
            github_owner: None,
            deployment_id: None,
            created_at: Utc::now().to_rfc3339(),
            last_heartbeat_at: None,
        }
    }

    #[test]
    fn insert_and_get_agent() {
        let db = setup_db();
        let agent = make_agent("a1", "vm-1");
        insert_agent(&db, &agent).unwrap();
        let fetched = get_agent(&db, "a1").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().vm_name, "vm-1");
    }

    #[test]
    fn list_and_delete_agents() {
        let db = setup_db();
        insert_agent(&db, &make_agent("a1", "vm-1")).unwrap();
        insert_agent(&db, &make_agent("a2", "vm-2")).unwrap();

        let all = list_agents(&db).unwrap();
        assert_eq!(all.len(), 2);

        assert!(delete_agent(&db, "a1").unwrap());
        let all = list_agents(&db).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn update_status_and_heartbeat() {
        let db = setup_db();
        insert_agent(&db, &make_agent("a1", "vm-1")).unwrap();

        assert!(update_agent_status(&db, "a1", "deployed").unwrap());
        let agent = get_agent(&db, "a1").unwrap().unwrap();
        assert_eq!(agent.status, "deployed");

        assert!(update_heartbeat(&db, "a1").unwrap());
        let agent = get_agent(&db, "a1").unwrap().unwrap();
        assert!(agent.last_heartbeat_at.is_some());
    }

    #[test]
    fn find_available_agent_filters() {
        let db = setup_db();
        let mut agent = make_agent("a1", "vm-1");
        agent.node_size = Some("large".into());
        insert_agent(&db, &agent).unwrap();

        // Should find it without filters
        let found = find_available_agent(&db, None, None).unwrap();
        assert!(found.is_some());

        // Should find it with matching filter
        let found = find_available_agent(&db, Some("large"), None).unwrap();
        assert!(found.is_some());

        // Should not find with non-matching filter
        let found = find_available_agent(&db, Some("small"), None).unwrap();
        assert!(found.is_none());
    }
}
