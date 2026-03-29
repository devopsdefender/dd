use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVersionRow {
    pub id: String,
    pub app_id: String,
    pub version: String,
    pub image_digest: Option<String>,
    pub compose: Option<String>,
    pub config: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployGrantRow {
    pub id: String,
    pub app_id: String,
    pub account_id: String,
    pub granted_by: String,
    pub created_at: String,
}

fn row_to_app(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppRow> {
    Ok(AppRow {
        id: row.get("id")?,
        name: row.get("name")?,
        description: row.get("description")?,
        owner_id: row.get("owner_id")?,
        created_at: row.get("created_at")?,
    })
}

fn row_to_version(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppVersionRow> {
    Ok(AppVersionRow {
        id: row.get("id")?,
        app_id: row.get("app_id")?,
        version: row.get("version")?,
        image_digest: row.get("image_digest")?,
        compose: row.get("compose")?,
        config: row.get("config")?,
        created_at: row.get("created_at")?,
    })
}

fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeployGrantRow> {
    Ok(DeployGrantRow {
        id: row.get("id")?,
        app_id: row.get("app_id")?,
        account_id: row.get("account_id")?,
        granted_by: row.get("granted_by")?,
        created_at: row.get("created_at")?,
    })
}

// -- Apps --

pub fn insert_app(db: &Db, app: &AppRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO apps (id, name, description, owner_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            app.id,
            app.name,
            app.description,
            app.owner_id,
            app.created_at
        ],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict("app with this name already exists".into())
        }
        _ => AppError::Internal,
    })?;
    Ok(())
}

pub fn get_app(db: &Db, id: &str) -> AppResult<Option<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, name, description, owner_id, created_at FROM apps WHERE id = ?1")
        .map_err(|_| AppError::Internal)?;
    stmt.query_row(params![id], row_to_app)
        .optional()
        .map_err(|_| AppError::Internal)
}

pub fn get_app_by_name(db: &Db, name: &str) -> AppResult<Option<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, name, description, owner_id, created_at FROM apps WHERE name = ?1")
        .map_err(|_| AppError::Internal)?;
    stmt.query_row(params![name], row_to_app)
        .optional()
        .map_err(|_| AppError::Internal)
}

pub fn list_apps(db: &Db) -> AppResult<Vec<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, description, owner_id, created_at \
             FROM apps ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map([], row_to_app)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
}

pub fn delete_app(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute("DELETE FROM apps WHERE id = ?1", params![id])
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

// -- App Versions --

pub fn insert_version(db: &Db, v: &AppVersionRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_versions (id, app_id, version, image_digest, compose, config, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![v.id, v.app_id, v.version, v.image_digest, v.compose, v.config, v.created_at],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn get_version(db: &Db, id: &str) -> AppResult<Option<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, version, image_digest, compose, config, created_at \
             FROM app_versions WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;
    stmt.query_row(params![id], row_to_version)
        .optional()
        .map_err(|_| AppError::Internal)
}

pub fn list_versions(db: &Db, app_id: &str) -> AppResult<Vec<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, version, image_digest, compose, config, created_at \
             FROM app_versions WHERE app_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![app_id], row_to_version)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
}

/// Find a version by app name + version string.
pub fn find_version(db: &Db, app_name: &str, version: &str) -> AppResult<Option<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT v.id, v.app_id, v.version, v.image_digest, v.compose, v.config, v.created_at \
             FROM app_versions v JOIN apps a ON v.app_id = a.id \
             WHERE a.name = ?1 AND v.version = ?2",
        )
        .map_err(|_| AppError::Internal)?;
    stmt.query_row(params![app_name, version], row_to_version)
        .optional()
        .map_err(|_| AppError::Internal)
}

/// Check if the deploy image matches a registered version's digest.
pub fn verify_image_digest(db: &Db, app_name: &str, image: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM app_versions v JOIN apps a ON v.app_id = a.id \
             WHERE a.name = ?1 AND v.image_digest = ?2",
            params![app_name, image],
            |row| row.get(0),
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

// -- Deploy Grants --

pub fn insert_grant(db: &Db, g: &DeployGrantRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_deploy_grants (id, app_id, account_id, granted_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![g.id, g.app_id, g.account_id, g.granted_by, g.created_at],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict("deploy grant already exists".into())
        }
        _ => AppError::Internal,
    })?;
    Ok(())
}

pub fn list_grants(db: &Db, app_id: &str) -> AppResult<Vec<DeployGrantRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, account_id, granted_by, created_at \
             FROM app_deploy_grants WHERE app_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![app_id], row_to_grant)
        .map_err(|_| AppError::Internal)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::Internal)
}

pub fn delete_grant(db: &Db, app_id: &str, account_id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "DELETE FROM app_deploy_grants WHERE app_id = ?1 AND account_id = ?2",
            params![app_id, account_id],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Check if an account can deploy an app.
/// True if: no owner (open), account is owner, or account has a grant.
pub fn can_deploy(db: &Db, app_id: &str, account_id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let owner_id: Option<String> = conn
        .query_row(
            "SELECT owner_id FROM apps WHERE id = ?1",
            params![app_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| AppError::Internal)?
        .flatten();

    match owner_id {
        None => Ok(true),
        Some(ref oid) if oid == account_id => Ok(true),
        Some(_) => {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM app_deploy_grants \
                     WHERE app_id = ?1 AND account_id = ?2",
                    params![app_id, account_id],
                    |row| row.get(0),
                )
                .map_err(|_| AppError::Internal)?;
            Ok(count > 0)
        }
    }
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

    fn make_app(id: &str, name: &str) -> AppRow {
        AppRow {
            id: id.into(),
            name: name.into(),
            description: None,
            owner_id: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn app_crud() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "my-app")).unwrap();
        assert!(get_app(&db, "a1").unwrap().is_some());
        assert!(get_app_by_name(&db, "my-app").unwrap().is_some());
        assert_eq!(list_apps(&db).unwrap().len(), 1);
        assert!(delete_app(&db, "a1").unwrap());
        assert_eq!(list_apps(&db).unwrap().len(), 0);
    }

    #[test]
    fn duplicate_name_conflict() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "dup")).unwrap();
        assert!(insert_app(&db, &make_app("a2", "dup")).is_err());
    }

    #[test]
    fn version_with_image_digest() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "my-app")).unwrap();
        let v = AppVersionRow {
            id: "v1".into(),
            app_id: "a1".into(),
            version: "1.0.0".into(),
            image_digest: Some("sha256:abc123".into()),
            compose: None,
            config: None,
            created_at: Utc::now().to_rfc3339(),
        };
        insert_version(&db, &v).unwrap();

        assert!(verify_image_digest(&db, "my-app", "sha256:abc123").unwrap());
        assert!(!verify_image_digest(&db, "my-app", "sha256:wrong").unwrap());
    }

    #[test]
    fn owner_controls_deploy() {
        let db = setup_db();
        let mut app = make_app("a1", "owned");
        app.owner_id = Some("owner-1".into());
        insert_app(&db, &app).unwrap();

        assert!(can_deploy(&db, "a1", "owner-1").unwrap());
        assert!(!can_deploy(&db, "a1", "stranger").unwrap());

        // Grant
        insert_grant(
            &db,
            &DeployGrantRow {
                id: "g1".into(),
                app_id: "a1".into(),
                account_id: "friend".into(),
                granted_by: "owner-1".into(),
                created_at: Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
        assert!(can_deploy(&db, "a1", "friend").unwrap());

        // Revoke
        delete_grant(&db, "a1", "friend").unwrap();
        assert!(!can_deploy(&db, "a1", "friend").unwrap());
    }

    #[test]
    fn unowned_app_open_to_all() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "open")).unwrap();
        assert!(can_deploy(&db, "a1", "anyone").unwrap());
    }
}
