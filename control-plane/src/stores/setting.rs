use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Key-value settings store backed by SQLite.
#[derive(Clone)]
pub struct SettingsStore {
    db: Db,
}

impl SettingsStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Get a setting value by key.
    pub fn get(&self, key: &str) -> AppResult<Option<String>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|_| AppError::Internal)?;

        let result = stmt
            .query_row(params![key], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|_| AppError::Internal)?;

        Ok(result)
    }

    /// Set a setting value (upsert).
    pub fn set(&self, key: &str, value: &str) -> AppResult<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|_| AppError::Internal)?;

        Ok(())
    }

    /// Delete a setting by key.
    pub fn delete(&self, key: &str) -> AppResult<bool> {
        let conn = self.db.lock().unwrap();
        let count = conn
            .execute("DELETE FROM settings WHERE key = ?1", params![key])
            .map_err(|_| AppError::Internal)?;
        Ok(count > 0)
    }

    /// List all settings.
    pub fn list(&self) -> AppResult<Vec<(String, String)>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT key, value FROM settings ORDER BY key")
            .map_err(|_| AppError::Internal)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| AppError::Internal)?;

        let mut settings = Vec::new();
        for row in rows {
            settings.push(row.map_err(|_| AppError::Internal)?);
        }
        Ok(settings)
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

    fn setup() -> SettingsStore {
        let db = db::connect_and_migrate("sqlite://:memory:").unwrap();
        SettingsStore::new(db)
    }

    #[test]
    fn get_set_delete() {
        let store = setup();

        assert!(store.get("foo").unwrap().is_none());

        store.set("foo", "bar").unwrap();
        assert_eq!(store.get("foo").unwrap(), Some("bar".into()));

        // Upsert
        store.set("foo", "baz").unwrap();
        assert_eq!(store.get("foo").unwrap(), Some("baz".into()));

        assert!(store.delete("foo").unwrap());
        assert!(store.get("foo").unwrap().is_none());
    }

    #[test]
    fn list_settings() {
        let store = setup();
        store.set("a", "1").unwrap();
        store.set("b", "2").unwrap();

        let all = store.list().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, "a");
        assert_eq!(all[1].0, "b");
    }
}
