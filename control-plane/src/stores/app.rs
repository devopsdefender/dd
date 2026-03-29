use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// App record as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<String>,
    pub created_at: String,
}

/// App version record as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVersionRow {
    pub id: String,
    pub app_id: String,
    pub version: String,
    pub compose: Option<String>,
    pub config: Option<String>,
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

fn row_to_app_version(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppVersionRow> {
    Ok(AppVersionRow {
        id: row.get("id")?,
        app_id: row.get("app_id")?,
        version: row.get("version")?,
        compose: row.get("compose")?,
        config: row.get("config")?,
        created_at: row.get("created_at")?,
    })
}

pub fn insert_app(db: &Db, app: &AppRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO apps (id, name, description, owner_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![app.id, app.name, app.description, app.owner_id, app.created_at],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, ref msg)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            let detail = msg.as_deref().unwrap_or("");
            if detail.contains("UNIQUE") || detail.contains("apps.name") {
                AppError::Conflict("app with this name already exists".into())
            } else {
                AppError::InvalidInput(format!("constraint violation: {detail}"))
            }
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
    let result = stmt
        .query_row(params![id], row_to_app)
        .optional()
        .map_err(|_| AppError::Internal)?;
    Ok(result)
}

pub fn get_app_by_name(db: &Db, name: &str) -> AppResult<Option<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, name, description, owner_id, created_at FROM apps WHERE name = ?1")
        .map_err(|_| AppError::Internal)?;
    let result = stmt
        .query_row(params![name], row_to_app)
        .optional()
        .map_err(|_| AppError::Internal)?;
    Ok(result)
}

pub fn list_apps(db: &Db) -> AppResult<Vec<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, description, owner_id, created_at FROM apps ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map([], row_to_app)
        .map_err(|_| AppError::Internal)?;
    let mut apps = Vec::new();
    for row in rows {
        apps.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(apps)
}

pub fn delete_app(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute("DELETE FROM apps WHERE id = ?1", params![id])
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

pub fn insert_app_version(db: &Db, version: &AppVersionRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_versions (id, app_id, version, compose, config, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            version.id,
            version.app_id,
            version.version,
            version.compose,
            version.config,
            version.created_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;
    Ok(())
}

pub fn get_app_version(db: &Db, id: &str) -> AppResult<Option<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, version, compose, config, created_at \
             FROM app_versions WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;
    let result = stmt
        .query_row(params![id], row_to_app_version)
        .optional()
        .map_err(|_| AppError::Internal)?;
    Ok(result)
}

pub fn list_app_versions(db: &Db, app_id: &str) -> AppResult<Vec<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, version, compose, config, created_at \
             FROM app_versions WHERE app_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![app_id], row_to_app_version)
        .map_err(|_| AppError::Internal)?;
    let mut versions = Vec::new();
    for row in rows {
        versions.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(versions)
}

pub fn find_app_version(
    db: &Db,
    app_name: &str,
    version: &str,
) -> AppResult<Option<AppVersionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT v.id, v.app_id, v.version, v.compose, v.config, v.created_at \
             FROM app_versions v JOIN apps a ON v.app_id = a.id \
             WHERE a.name = ?1 AND v.version = ?2",
        )
        .map_err(|_| AppError::Internal)?;
    let result = stmt
        .query_row(params![app_name, version], row_to_app_version)
        .optional()
        .map_err(|_| AppError::Internal)?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Deploy Grants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployGrantRow {
    pub id: String,
    pub app_id: String,
    pub account_id: String,
    pub granted_by: String,
    pub created_at: String,
}

fn row_to_deploy_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeployGrantRow> {
    Ok(DeployGrantRow {
        id: row.get("id")?,
        app_id: row.get("app_id")?,
        account_id: row.get("account_id")?,
        granted_by: row.get("granted_by")?,
        created_at: row.get("created_at")?,
    })
}

pub fn insert_deploy_grant(db: &Db, grant: &DeployGrantRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO app_deploy_grants (id, app_id, account_id, granted_by, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            grant.id,
            grant.app_id,
            grant.account_id,
            grant.granted_by,
            grant.created_at,
        ],
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

pub fn list_deploy_grants(db: &Db, app_id: &str) -> AppResult<Vec<DeployGrantRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, app_id, account_id, granted_by, created_at \
             FROM app_deploy_grants WHERE app_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;
    let rows = stmt
        .query_map(params![app_id], row_to_deploy_grant)
        .map_err(|_| AppError::Internal)?;
    let mut grants = Vec::new();
    for row in rows {
        grants.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(grants)
}

pub fn delete_deploy_grant(db: &Db, app_id: &str, account_id: &str) -> AppResult<bool> {
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
/// Returns true if: app has no owner, account is the owner, or account has a deploy grant.
pub fn can_deploy(db: &Db, app_id: &str, account_id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    // Check if app has no owner (backward compat) or account is owner
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
        None => Ok(true),                               // No owner → anyone can deploy
        Some(ref oid) if oid == account_id => Ok(true), // Is the owner
        Some(_) => {
            // Check for deploy grant
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM app_deploy_grants WHERE app_id = ?1 AND account_id = ?2",
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
            description: Some("test app".into()),
            owner_id: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    fn make_version(id: &str, app_id: &str, version: &str) -> AppVersionRow {
        AppVersionRow {
            id: id.into(),
            app_id: app_id.into(),
            version: version.into(),
            compose: None,
            config: None,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn insert_and_get_app() {
        let db = setup_db();
        let app = make_app("a1", "measurer");
        insert_app(&db, &app).unwrap();
        let fetched = get_app(&db, "a1").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "measurer");
    }

    #[test]
    fn duplicate_name_returns_conflict() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "measurer")).unwrap();
        let result = insert_app(&db, &make_app("a2", "measurer"));
        assert!(result.is_err());
    }

    #[test]
    fn list_and_delete_apps() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "app-one")).unwrap();
        insert_app(&db, &make_app("a2", "app-two")).unwrap();
        assert_eq!(list_apps(&db).unwrap().len(), 2);

        assert!(delete_app(&db, "a1").unwrap());
        assert_eq!(list_apps(&db).unwrap().len(), 1);
    }

    #[test]
    fn get_app_by_name_works() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "measurer")).unwrap();
        let fetched = get_app_by_name(&db, "measurer").unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().id, "a1");

        let missing = get_app_by_name(&db, "nonexistent").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn insert_and_list_versions() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "measurer")).unwrap();
        insert_app_version(&db, &make_version("v1", "a1", "1.0.0")).unwrap();
        insert_app_version(&db, &make_version("v2", "a1", "1.1.0")).unwrap();

        let versions = list_app_versions(&db, "a1").unwrap();
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn find_app_version_by_name_and_version() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "measurer")).unwrap();
        insert_app_version(&db, &make_version("v1", "a1", "1.0.0")).unwrap();

        let found = find_app_version(&db, "measurer", "1.0.0").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "v1");

        let missing = find_app_version(&db, "measurer", "9.9.9").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn can_deploy_no_owner_allows_anyone() {
        let db = setup_db();
        insert_app(&db, &make_app("a1", "open-app")).unwrap();
        assert!(can_deploy(&db, "a1", "random-account").unwrap());
    }

    #[test]
    fn can_deploy_owner_only() {
        let db = setup_db();
        let mut app = make_app("a1", "owned-app");
        app.owner_id = Some("owner-1".into());
        insert_app(&db, &app).unwrap();

        // Owner can deploy
        assert!(can_deploy(&db, "a1", "owner-1").unwrap());
        // Non-owner cannot
        assert!(!can_deploy(&db, "a1", "random-account").unwrap());
    }

    #[test]
    fn can_deploy_with_grant() {
        let db = setup_db();
        let mut app = make_app("a1", "owned-app");
        app.owner_id = Some("owner-1".into());
        insert_app(&db, &app).unwrap();

        // Grant deploy rights
        let grant = DeployGrantRow {
            id: "g1".into(),
            app_id: "a1".into(),
            account_id: "deployer-1".into(),
            granted_by: "owner-1".into(),
            created_at: Utc::now().to_rfc3339(),
        };
        insert_deploy_grant(&db, &grant).unwrap();

        // Granted account can deploy
        assert!(can_deploy(&db, "a1", "deployer-1").unwrap());
        // Unganted account still cannot
        assert!(!can_deploy(&db, "a1", "random-account").unwrap());

        // Revoke
        assert!(delete_deploy_grant(&db, "a1", "deployer-1").unwrap());
        assert!(!can_deploy(&db, "a1", "deployer-1").unwrap());
    }
}
