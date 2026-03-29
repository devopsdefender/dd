use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

// ---------------------------------------------------------------------------
// Trusted Measurers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurerRow {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub agent_id: Option<String>,
    pub mrtd: Option<String>,
    pub measurement_types: String,
    pub status: String,
    pub created_at: String,
}

fn row_to_measurer(row: &rusqlite::Row<'_>) -> rusqlite::Result<MeasurerRow> {
    Ok(MeasurerRow {
        id: row.get("id")?,
        name: row.get("name")?,
        public_key: row.get("public_key")?,
        agent_id: row.get("agent_id")?,
        mrtd: row.get("mrtd")?,
        measurement_types: row.get("measurement_types")?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
    })
}

pub fn insert_measurer(db: &Db, m: &MeasurerRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO trusted_measurers \
         (id, name, public_key, agent_id, mrtd, measurement_types, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            m.id,
            m.name,
            m.public_key,
            m.agent_id,
            m.mrtd,
            m.measurement_types,
            m.status,
            m.created_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn get_measurer(db: &Db, id: &str) -> AppResult<Option<MeasurerRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, public_key, agent_id, mrtd, measurement_types, status, created_at \
             FROM trusted_measurers WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;
    let result = stmt
        .query_row(params![id], row_to_measurer)
        .optional()
        .map_err(|_| AppError::Internal)?;
    Ok(result)
}

pub fn list_measurers(db: &Db) -> AppResult<Vec<MeasurerRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, public_key, agent_id, mrtd, measurement_types, status, created_at \
             FROM trusted_measurers ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map([], row_to_measurer)
        .map_err(|_| AppError::Internal)?;
    let mut measurers = Vec::new();
    for row in rows {
        measurers.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(measurers)
}

pub fn revoke_measurer(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE trusted_measurers SET status = 'revoked' WHERE id = ?1",
            params![id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementRow {
    pub id: String,
    pub measurer_id: String,
    pub measurement_type: String,
    pub app_id: Option<String>,
    pub version_id: Option<String>,
    pub image_digest: Option<String>,
    pub agent_id: Option<String>,
    pub node_mrtd: Option<String>,
    pub measurement_hash: String,
    pub signature: String,
    pub report: String,
    pub status: String,
    pub measured_at: String,
}

fn row_to_measurement(row: &rusqlite::Row<'_>) -> rusqlite::Result<MeasurementRow> {
    Ok(MeasurementRow {
        id: row.get("id")?,
        measurer_id: row.get("measurer_id")?,
        measurement_type: row.get("measurement_type")?,
        app_id: row.get("app_id")?,
        version_id: row.get("version_id")?,
        image_digest: row.get("image_digest")?,
        agent_id: row.get("agent_id")?,
        node_mrtd: row.get("node_mrtd")?,
        measurement_hash: row.get("measurement_hash")?,
        signature: row.get("signature")?,
        report: row.get("report")?,
        status: row.get("status")?,
        measured_at: row.get("measured_at")?,
    })
}

pub fn insert_measurement(db: &Db, m: &MeasurementRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO measurements \
         (id, measurer_id, measurement_type, app_id, version_id, image_digest, \
          agent_id, node_mrtd, measurement_hash, signature, report, status, measured_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            m.id,
            m.measurer_id,
            m.measurement_type,
            m.app_id,
            m.version_id,
            m.image_digest,
            m.agent_id,
            m.node_mrtd,
            m.measurement_hash,
            m.signature,
            m.report,
            m.status,
            m.measured_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn list_measurements_for_app_version(
    db: &Db,
    app_id: &str,
    version_id: &str,
) -> AppResult<Vec<MeasurementRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, measurer_id, measurement_type, app_id, version_id, image_digest, \
             agent_id, node_mrtd, measurement_hash, signature, report, status, measured_at \
             FROM measurements \
             WHERE measurement_type = 'app' AND app_id = ?1 AND version_id = ?2 \
             ORDER BY measured_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![app_id, version_id], row_to_measurement)
        .map_err(|_| AppError::Internal)?;
    let mut measurements = Vec::new();
    for row in rows {
        measurements.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(measurements)
}

pub fn list_measurements_for_agent(db: &Db, agent_id: &str) -> AppResult<Vec<MeasurementRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, measurer_id, measurement_type, app_id, version_id, image_digest, \
             agent_id, node_mrtd, measurement_hash, signature, report, status, measured_at \
             FROM measurements \
             WHERE measurement_type = 'node' AND agent_id = ?1 \
             ORDER BY measured_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![agent_id], row_to_measurement)
        .map_err(|_| AppError::Internal)?;
    let mut measurements = Vec::new();
    for row in rows {
        measurements.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(measurements)
}

/// Check if an app version has at least one valid measurement from an active measurer.
pub fn has_valid_measurement(db: &Db, app_id: &str, version_id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM measurements m \
             JOIN trusted_measurers tm ON m.measurer_id = tm.id \
             WHERE m.measurement_type = 'app' \
             AND m.app_id = ?1 AND m.version_id = ?2 \
             AND m.status = 'valid' AND tm.status = 'active'",
            params![app_id, version_id],
            |row| row.get(0),
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
    use crate::stores::app;
    use chrono::Utc;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    fn make_measurer(id: &str, name: &str) -> MeasurerRow {
        MeasurerRow {
            id: id.into(),
            name: name.into(),
            public_key: "test-key-base64".into(),
            agent_id: None,
            mrtd: None,
            measurement_types: "app,node".into(),
            status: "active".into(),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn insert_and_list_measurers() {
        let db = setup_db();
        insert_measurer(&db, &make_measurer("m1", "security-co")).unwrap();
        insert_measurer(&db, &make_measurer("m2", "dc-operator")).unwrap();
        let all = list_measurers(&db).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn revoke_measurer_works() {
        let db = setup_db();
        insert_measurer(&db, &make_measurer("m1", "security-co")).unwrap();
        assert!(revoke_measurer(&db, "m1").unwrap());
        let m = get_measurer(&db, "m1").unwrap().unwrap();
        assert_eq!(m.status, "revoked");
    }

    #[test]
    fn has_valid_measurement_checks_active_measurer() {
        let db = setup_db();

        // Create app + version
        let a = app::AppRow {
            id: "a1".into(),
            name: "test-app".into(),
            description: None,
            created_at: Utc::now().to_rfc3339(),
        };
        app::insert_app(&db, &a).unwrap();
        let v = app::AppVersionRow {
            id: "v1".into(),
            app_id: "a1".into(),
            version: "1.0.0".into(),
            compose: None,
            config: None,
            created_at: Utc::now().to_rfc3339(),
        };
        app::insert_app_version(&db, &v).unwrap();

        // No measurement yet
        assert!(!has_valid_measurement(&db, "a1", "v1").unwrap());

        // Add measurer + measurement
        insert_measurer(&db, &make_measurer("m1", "security-co")).unwrap();
        let measurement = MeasurementRow {
            id: "meas1".into(),
            measurer_id: "m1".into(),
            measurement_type: "app".into(),
            app_id: Some("a1".into()),
            version_id: Some("v1".into()),
            image_digest: Some("sha256:abc".into()),
            agent_id: None,
            node_mrtd: None,
            measurement_hash: "hash123".into(),
            signature: "sig123".into(),
            report: "{}".into(),
            status: "valid".into(),
            measured_at: Utc::now().to_rfc3339(),
        };
        insert_measurement(&db, &measurement).unwrap();
        assert!(has_valid_measurement(&db, "a1", "v1").unwrap());

        // Revoke measurer → measurement no longer trusted
        revoke_measurer(&db, "m1").unwrap();
        assert!(!has_valid_measurement(&db, "a1", "v1").unwrap());
    }
}
