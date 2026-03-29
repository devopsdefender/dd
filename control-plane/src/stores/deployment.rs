use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Deployment record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeploymentRow {
    pub id: String,
    pub agent_id: String,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub compose: Option<String>,
    pub image: Option<String>,
    pub env: Option<String>,
    pub cmd: Option<String>,
    pub ports: Option<String>,
    pub config: Option<String>,
    pub status: String,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub previous_deployment_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn row_to_deployment(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeploymentRow> {
    Ok(DeploymentRow {
        id: row.get("id")?,
        agent_id: row.get("agent_id")?,
        app_name: row.get("app_name")?,
        app_version: row.get("app_version")?,
        compose: row.get("compose")?,
        image: row.get("image")?,
        env: row.get("env")?,
        cmd: row.get("cmd")?,
        ports: row.get("ports")?,
        config: row.get("config")?,
        status: row.get("status")?,
        error_message: row.get("error_message")?,
        previous_deployment_id: row.get("previous_deployment_id")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

const SELECT_COLS: &str = "id, agent_id, app_name, app_version, compose, image, env, cmd, ports, \
    config, status, error_message, previous_deployment_id, created_at, updated_at";

/// Insert a new deployment.
pub fn insert_deployment(db: &Db, dep: &DeploymentRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO deployments (id, agent_id, app_name, app_version, compose, image, env, cmd, ports, \
         config, status, error_message, previous_deployment_id, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            dep.id,
            dep.agent_id,
            dep.app_name,
            dep.app_version,
            dep.compose,
            dep.image,
            dep.env,
            dep.cmd,
            dep.ports,
            dep.config,
            dep.status,
            dep.error_message,
            dep.previous_deployment_id,
            dep.created_at,
            dep.updated_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

/// Get a deployment by ID.
pub fn get_deployment(db: &Db, id: &str) -> AppResult<Option<DeploymentRow>> {
    let conn = db.lock().unwrap();
    let query = format!("SELECT {SELECT_COLS} FROM deployments WHERE id = ?1");
    let mut stmt = conn.prepare(&query).map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![id], row_to_deployment)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// List deployments, optionally filtering by agent_id.
pub fn list_deployments(db: &Db, agent_id: Option<&str>) -> AppResult<Vec<DeploymentRow>> {
    let conn = db.lock().unwrap();

    let (query, bind_val) = if let Some(aid) = agent_id {
        (
            format!(
                "SELECT {SELECT_COLS} FROM deployments WHERE agent_id = ?1 ORDER BY created_at DESC"
            ),
            Some(aid.to_string()),
        )
    } else {
        (
            format!("SELECT {SELECT_COLS} FROM deployments ORDER BY created_at DESC"),
            None,
        )
    };

    let mut stmt = conn.prepare(&query).map_err(|_| AppError::Internal)?;

    let rows = if let Some(ref v) = bind_val {
        stmt.query_map(params![v], row_to_deployment)
            .map_err(|_| AppError::Internal)?
    } else {
        stmt.query_map([], row_to_deployment)
            .map_err(|_| AppError::Internal)?
    };

    let mut deployments = Vec::new();
    for row in rows {
        deployments.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(deployments)
}

/// List pending deployments for a specific agent.
pub fn list_pending_deployments(db: &Db, agent_id: &str) -> AppResult<Vec<DeploymentRow>> {
    let conn = db.lock().unwrap();
    let query = format!(
        "SELECT {SELECT_COLS} FROM deployments \
         WHERE agent_id = ?1 AND status = 'pending' ORDER BY created_at ASC"
    );
    let mut stmt = conn.prepare(&query).map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![agent_id], row_to_deployment)
        .map_err(|_| AppError::Internal)?;

    let mut deployments = Vec::new();
    for row in rows {
        deployments.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(deployments)
}

/// Update deployment status.
pub fn update_deployment_status(db: &Db, id: &str, status: &str) -> AppResult<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE deployments SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Update deployment status with an error message.
pub fn update_deployment_status_with_error(
    db: &Db,
    id: &str,
    status: &str,
    error_message: Option<&str>,
) -> AppResult<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE deployments SET status = ?1, error_message = ?2, updated_at = ?3 WHERE id = ?4",
            params![status, error_message, now, id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

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
    use crate::stores::agent as agent_store;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    fn ensure_agent(db: &Db, agent_id: &str) {
        let agent = agent_store::AgentRow {
            id: agent_id.into(),
            vm_name: format!("vm-{agent_id}"),
            status: "undeployed".into(),
            registration_state: "ready".into(),
            hostname: None,
            tunnel_id: None,
            mrtd: None,
            tcb_status: None,
            node_size: None,
            datacenter: None,
            github_owner: None,
            attestation_token: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat_at: None,
        };
        // Ignore error if agent already exists
        let _ = agent_store::insert_agent(db, &agent);
    }

    fn make_deployment(id: &str, agent_id: &str) -> DeploymentRow {
        let now = chrono::Utc::now().to_rfc3339();
        DeploymentRow {
            id: id.into(),
            agent_id: agent_id.into(),
            app_name: Some("test-app".into()),
            app_version: Some("1.0.0".into()),
            compose: None,
            image: Some("nginx:latest".into()),
            env: None,
            cmd: None,
            ports: None,
            config: None,
            status: "pending".into(),
            error_message: None,
            previous_deployment_id: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn insert_and_get_deployment() {
        let db = setup_db();
        ensure_agent(&db, "a1");
        let dep = make_deployment("d1", "a1");
        insert_deployment(&db, &dep).unwrap();

        let fetched = get_deployment(&db, "d1").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().app_name, Some("test-app".into()));
    }

    #[test]
    fn list_deployments_filters_by_agent() {
        let db = setup_db();
        ensure_agent(&db, "a1");
        ensure_agent(&db, "a2");
        insert_deployment(&db, &make_deployment("d1", "a1")).unwrap();
        insert_deployment(&db, &make_deployment("d2", "a2")).unwrap();

        let all = list_deployments(&db, None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = list_deployments(&db, Some("a1")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].agent_id, "a1");
    }

    #[test]
    fn update_deployment_status_works() {
        let db = setup_db();
        ensure_agent(&db, "a1");
        insert_deployment(&db, &make_deployment("d1", "a1")).unwrap();

        update_deployment_status(&db, "d1", "running").unwrap();
        let dep = get_deployment(&db, "d1").unwrap().unwrap();
        assert_eq!(dep.status, "running");
    }
}
