use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Admin session record.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Insert a new session.
pub fn insert_session(db: &Db, session: &SessionRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO admin_sessions (id, token_hash, token_prefix, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            session.id,
            session.token_hash,
            session.token_prefix,
            session.created_at,
            session.expires_at,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

/// Find a session by token prefix.
pub fn find_by_prefix(db: &Db, prefix: &str) -> AppResult<Option<SessionRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, token_hash, token_prefix, created_at, expires_at \
             FROM admin_sessions WHERE token_prefix = ?1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![prefix], |row| {
            Ok(SessionRow {
                id: row.get("id")?,
                token_hash: row.get("token_hash")?,
                token_prefix: row.get("token_prefix")?,
                created_at: row.get("created_at")?,
                expires_at: row.get("expires_at")?,
            })
        })
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// Delete a session by ID.
pub fn delete_session(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute("DELETE FROM admin_sessions WHERE id = ?1", params![id])
        .map_err(|_| AppError::Internal)?;
    Ok(count > 0)
}

/// Delete expired sessions.
pub fn cleanup_expired(db: &Db) -> AppResult<u64> {
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "DELETE FROM admin_sessions WHERE expires_at < ?1",
            params![now],
        )
        .map_err(|_| AppError::Internal)?;
    Ok(count as u64)
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

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    #[test]
    fn insert_and_find_session() {
        let db = setup_db();
        let session = SessionRow {
            id: "s1".into(),
            token_hash: "hash123".into(),
            token_prefix: "dds_abcdefgh".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        };
        insert_session(&db, &session).unwrap();

        let found = find_by_prefix(&db, "dds_abcdefgh").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "s1");
    }

    #[test]
    fn cleanup_expired_sessions() {
        let db = setup_db();
        let expired = SessionRow {
            id: "s1".into(),
            token_hash: "hash".into(),
            token_prefix: "dds_expired1".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        };
        let valid = SessionRow {
            id: "s2".into(),
            token_hash: "hash".into(),
            token_prefix: "dds_valid123".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        };
        insert_session(&db, &expired).unwrap();
        insert_session(&db, &valid).unwrap();

        let removed = cleanup_expired(&db).unwrap();
        assert_eq!(removed, 1);

        // Valid session still there
        let found = find_by_prefix(&db, "dds_valid123").unwrap();
        assert!(found.is_some());
    }
}
