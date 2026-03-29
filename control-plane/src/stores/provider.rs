use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRow {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub agent_id: Option<String>,
    pub mrtd: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkuRow {
    pub id: String,
    pub provider_id: String,
    pub name: String,
    pub vcpu: i64,
    pub ram_gb: i64,
    pub gpu: Option<String>,
    pub region: Option<String>,
    pub available: i64,
    pub status: String,
    pub created_at: String,
}

fn row_to_provider(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderRow> {
    Ok(ProviderRow {
        id: row.get("id")?,
        name: row.get("name")?,
        public_key: row.get("public_key")?,
        agent_id: row.get("agent_id")?,
        mrtd: row.get("mrtd")?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
    })
}

fn row_to_sku(row: &rusqlite::Row<'_>) -> rusqlite::Result<SkuRow> {
    Ok(SkuRow {
        id: row.get("id")?,
        provider_id: row.get("provider_id")?,
        name: row.get("name")?,
        vcpu: row.get("vcpu")?,
        ram_gb: row.get("ram_gb")?,
        gpu: row.get("gpu")?,
        region: row.get("region")?,
        available: row.get("available")?,
        status: row.get("status")?,
        created_at: row.get("created_at")?,
    })
}

pub fn insert_provider(db: &Db, p: &ProviderRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO providers (id, name, public_key, agent_id, mrtd, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            p.id,
            p.name,
            p.public_key,
            p.agent_id,
            p.mrtd,
            p.status,
            p.created_at
        ],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn get_provider(db: &Db, id: &str) -> AppResult<Option<ProviderRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, public_key, agent_id, mrtd, status, created_at \
             FROM providers WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;
    stmt.query_row(params![id], row_to_provider)
        .optional()
        .map_err(|_| AppError::Internal)
}

pub fn list_providers(db: &Db) -> AppResult<Vec<ProviderRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, public_key, agent_id, mrtd, status, created_at \
             FROM providers ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map([], row_to_provider)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
}

pub fn revoke_provider(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE providers SET status = 'revoked' WHERE id = ?1",
            params![id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

pub fn insert_sku(db: &Db, sku: &SkuRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO provider_skus \
         (id, provider_id, name, vcpu, ram_gb, gpu, region, available, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            sku.id,
            sku.provider_id,
            sku.name,
            sku.vcpu,
            sku.ram_gb,
            sku.gpu,
            sku.region,
            sku.available,
            sku.status,
            sku.created_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn list_skus(db: &Db, provider_id: &str) -> AppResult<Vec<SkuRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, provider_id, name, vcpu, ram_gb, gpu, region, available, status, created_at \
             FROM provider_skus WHERE provider_id = ?1 ORDER BY name",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![provider_id], row_to_sku)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
}

pub fn list_all_skus(db: &Db) -> AppResult<Vec<SkuRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, provider_id, name, vcpu, ram_gb, gpu, region, available, status, created_at \
             FROM provider_skus WHERE status = 'active' ORDER BY name",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map([], row_to_sku)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
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
    use chrono::Utc;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    #[test]
    fn provider_crud() {
        let db = setup_db();
        let p = ProviderRow {
            id: "p1".into(),
            name: "dc-operator".into(),
            public_key: "key123".into(),
            agent_id: None,
            mrtd: None,
            status: "active".into(),
            created_at: Utc::now().to_rfc3339(),
        };
        insert_provider(&db, &p).unwrap();
        assert!(get_provider(&db, "p1").unwrap().is_some());
        assert_eq!(list_providers(&db).unwrap().len(), 1);

        revoke_provider(&db, "p1").unwrap();
        assert_eq!(get_provider(&db, "p1").unwrap().unwrap().status, "revoked");
    }

    #[test]
    fn sku_registration() {
        let db = setup_db();
        insert_provider(
            &db,
            &ProviderRow {
                id: "p1".into(),
                name: "dc".into(),
                public_key: "k".into(),
                agent_id: None,
                mrtd: None,
                status: "active".into(),
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();

        insert_sku(
            &db,
            &SkuRow {
                id: "s1".into(),
                provider_id: "p1".into(),
                name: "gpu-h100".into(),
                vcpu: 16,
                ram_gb: 64,
                gpu: Some("H100".into()),
                region: Some("ovh-eu".into()),
                available: 3,
                status: "active".into(),
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();

        assert_eq!(list_skus(&db, "p1").unwrap().len(), 1);
        assert_eq!(list_all_skus(&db).unwrap().len(), 1);
    }
}
