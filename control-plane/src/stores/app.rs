use serde::{Deserialize, Serialize};

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// App record as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

fn row_to_app(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppRow> {
    Ok(AppRow {
        id: row.get("id")?,
        name: row.get("name")?,
        description: row.get("description")?,
        created_at: row.get("created_at")?,
    })
}

/// List all apps.
pub fn list_apps(db: &Db) -> AppResult<Vec<AppRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, name, description, created_at FROM apps ORDER BY created_at DESC")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use rusqlite::params;

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    #[test]
    fn list_apps_empty() {
        let db = setup_db();
        let apps = list_apps(&db).unwrap();
        assert!(apps.is_empty());
    }

    #[test]
    fn list_apps_returns_inserted() {
        let db = setup_db();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO apps (id, name, description, created_at) VALUES (?1, ?2, ?3, ?4)",
                params!["app-1", "my-app", "A test app", "2025-01-01T00:00:00Z"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO apps (id, name, description, created_at) VALUES (?1, ?2, ?3, ?4)",
                params!["app-2", "other-app", None::<String>, "2025-01-02T00:00:00Z"],
            )
            .unwrap();
        }

        let apps = list_apps(&db).unwrap();
        assert_eq!(apps.len(), 2);
        // Ordered by created_at DESC
        assert_eq!(apps[0].name, "other-app");
        assert_eq!(apps[1].name, "my-app");
        assert!(apps[0].description.is_none());
        assert_eq!(apps[1].description.as_deref(), Some("A test app"));
    }
}
