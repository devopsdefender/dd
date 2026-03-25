use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Deployment record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeploymentRow {
    pub id: String,
    pub agent_id: String,
    pub image: String,
    pub env: Vec<String>,
    pub cmd: Vec<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

fn row_to_deployment(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeploymentRow> {
    let env_json: String = row.get("env")?;
    let cmd_json: String = row.get("cmd")?;
    Ok(DeploymentRow {
        id: row.get("id")?,
        agent_id: row.get("agent_id")?,
        image: row.get("image")?,
        env: serde_json::from_str(&env_json).map_err(serde_to_sql_error)?,
        cmd: serde_json::from_str(&cmd_json).map_err(serde_to_sql_error)?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

pub fn insert_deployment(db: &Db, dep: &DeploymentRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO deployments (id, agent_id, image, env, cmd, status, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            dep.id,
            dep.agent_id,
            dep.image,
            serde_json::to_string(&dep.env).map_err(|_| AppError::Internal)?,
            serde_json::to_string(&dep.cmd).map_err(|_| AppError::Internal)?,
            dep.status,
            dep.created_at,
            dep.updated_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

pub fn get_deployment(db: &Db, id: &str) -> AppResult<Option<DeploymentRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, image, env, cmd, status, created_at, updated_at \
             FROM deployments WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![id], row_to_deployment)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

pub fn list_deployments(db: &Db, agent_id: Option<&str>) -> AppResult<Vec<DeploymentRow>> {
    let conn = db.lock().unwrap();

    let (query, bind_val) = if let Some(aid) = agent_id {
        (
            "SELECT id, agent_id, image, env, cmd, status, created_at, updated_at \
             FROM deployments WHERE agent_id = ?1 ORDER BY created_at DESC",
            Some(aid.to_string()),
        )
    } else {
        (
            "SELECT id, agent_id, image, env, cmd, status, created_at, updated_at \
             FROM deployments ORDER BY created_at DESC",
            None,
        )
    };

    let mut stmt = conn.prepare(query).map_err(|_| AppError::Internal)?;
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

fn serde_to_sql_error(err: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
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
            deployment_id: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat_at: None,
        };
        let _ = agent_store::insert_agent(db, &agent);
    }

    fn make_deployment(id: &str, agent_id: &str) -> DeploymentRow {
        let now = chrono::Utc::now().to_rfc3339();
        DeploymentRow {
            id: id.into(),
            agent_id: agent_id.into(),
            image: "ghcr.io/devopsdefender/workload:latest".into(),
            env: vec!["KEY=VALUE".into()],
            cmd: vec!["/bin/server".into()],
            status: "pending".into(),
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

        let fetched = get_deployment(&db, "d1").unwrap().unwrap();
        assert_eq!(fetched.image, "ghcr.io/devopsdefender/workload:latest");
        assert_eq!(fetched.env, vec!["KEY=VALUE"]);
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
