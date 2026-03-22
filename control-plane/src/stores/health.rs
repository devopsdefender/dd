use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Health check record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckRow {
    pub id: String,
    pub agent_id: String,
    pub app_name: Option<String>,
    pub health_ok: bool,
    pub attestation_ok: bool,
    pub failure_reason: Option<String>,
    pub checked_at: String,
}

/// Insert a health check record.
pub fn insert_health_check(db: &Db, check: &HealthCheckRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_health_checks (id, agent_id, app_name, health_ok, attestation_ok, \
         failure_reason, checked_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            check.id,
            check.agent_id,
            check.app_name,
            check.health_ok,
            check.attestation_ok,
            check.failure_reason,
            check.checked_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

/// Get recent health checks for an agent.
pub fn get_recent_checks(db: &Db, agent_id: &str, limit: i64) -> AppResult<Vec<HealthCheckRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, app_name, health_ok, attestation_ok, failure_reason, checked_at \
             FROM app_health_checks WHERE agent_id = ?1 ORDER BY checked_at DESC LIMIT ?2",
        )
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map(params![agent_id, limit], |row| {
            Ok(HealthCheckRow {
                id: row.get("id")?,
                agent_id: row.get("agent_id")?,
                app_name: row.get("app_name")?,
                health_ok: row.get("health_ok")?,
                attestation_ok: row.get("attestation_ok")?,
                failure_reason: row.get("failure_reason")?,
                checked_at: row.get("checked_at")?,
            })
        })
        .map_err(|_| AppError::Internal)?;

    let mut checks = Vec::new();
    for row in rows {
        checks.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(checks)
}

/// Count consecutive failures for an agent.
pub fn count_consecutive_failures(db: &Db, agent_id: &str) -> AppResult<i64> {
    let checks = get_recent_checks(db, agent_id, 100)?;
    let mut count = 0i64;
    for check in &checks {
        if !check.health_ok {
            count += 1;
        } else {
            break;
        }
    }
    Ok(count)
}

/// Count consecutive successes for an agent.
pub fn count_consecutive_successes(db: &Db, agent_id: &str) -> AppResult<i64> {
    let checks = get_recent_checks(db, agent_id, 100)?;
    let mut count = 0i64;
    for check in &checks {
        if check.health_ok {
            count += 1;
        } else {
            break;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    #[test]
    fn insert_and_get_checks() {
        let db = setup_db();
        let check = HealthCheckRow {
            id: "c1".into(),
            agent_id: "a1".into(),
            app_name: Some("myapp".into()),
            health_ok: true,
            attestation_ok: true,
            failure_reason: None,
            checked_at: chrono::Utc::now().to_rfc3339(),
        };
        insert_health_check(&db, &check).unwrap();

        let checks = get_recent_checks(&db, "a1", 10).unwrap();
        assert_eq!(checks.len(), 1);
        assert!(checks[0].health_ok);
    }

    #[test]
    fn consecutive_failure_count() {
        let db = setup_db();
        let now = chrono::Utc::now();

        // Insert 3 failures then 1 success (in reverse chronological order for the query)
        for (i, ok) in [(0, false), (1, false), (2, false), (3, true)].iter() {
            let t = now - chrono::Duration::seconds(*i as i64);
            let check = HealthCheckRow {
                id: format!("c{i}"),
                agent_id: "a1".into(),
                app_name: None,
                health_ok: *ok,
                attestation_ok: true,
                failure_reason: None,
                checked_at: t.to_rfc3339(),
            };
            insert_health_check(&db, &check).unwrap();
        }

        let failures = count_consecutive_failures(&db, "a1").unwrap();
        assert_eq!(failures, 3);
    }
}
