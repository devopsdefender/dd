use rusqlite::params;

use crate::common::error::{AppError, AppResult};
use crate::db::Db;

/// Account record as stored in the database.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: String,
    pub name: String,
    pub account_type: String,
    pub api_key_hash: String,
    pub api_key_prefix: String,
    pub github_login: Option<String>,
    pub github_org: Option<String>,
    pub created_at: String,
    pub is_active: bool,
}

fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    Ok(AccountRow {
        id: row.get("id")?,
        name: row.get("name")?,
        account_type: row.get("account_type")?,
        api_key_hash: row.get("api_key_hash")?,
        api_key_prefix: row.get("api_key_prefix")?,
        github_login: row.get("github_login")?,
        github_org: row.get("github_org")?,
        created_at: row.get("created_at")?,
        is_active: row.get("is_active")?,
    })
}

/// Insert a new account.
pub fn insert_account(db: &Db, account: &AccountRow) -> AppResult<()> {
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO accounts (id, name, account_type, api_key_hash, api_key_prefix, \
         github_login, github_org, created_at, is_active) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            account.id,
            account.name,
            account.account_type,
            account.api_key_hash,
            account.api_key_prefix,
            account.github_login,
            account.github_org,
            account.created_at,
            account.is_active,
        ],
    )
    .map_err(|_| AppError::Internal)?;

    Ok(())
}

/// Find an account by API key prefix.
pub fn find_by_key_prefix(db: &Db, prefix: &str) -> AppResult<Option<AccountRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, account_type, api_key_hash, api_key_prefix, \
             github_login, github_org, created_at, is_active \
             FROM accounts WHERE api_key_prefix = ?1 AND is_active = 1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![prefix], row_to_account)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// Get an account by ID.
pub fn get_account(db: &Db, id: &str) -> AppResult<Option<AccountRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, account_type, api_key_hash, api_key_prefix, \
             github_login, github_org, created_at, is_active \
             FROM accounts WHERE id = ?1",
        )
        .map_err(|_| AppError::Internal)?;

    let result = stmt
        .query_row(params![id], row_to_account)
        .optional()
        .map_err(|_| AppError::Internal)?;

    Ok(result)
}

/// List all accounts.
pub fn list_accounts(db: &Db) -> AppResult<Vec<AccountRow>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, account_type, api_key_hash, api_key_prefix, \
             github_login, github_org, created_at, is_active \
             FROM accounts ORDER BY created_at DESC",
        )
        .map_err(|_| AppError::Internal)?;

    let rows = stmt
        .query_map([], row_to_account)
        .map_err(|_| AppError::Internal)?;

    let mut accounts = Vec::new();
    for row in rows {
        accounts.push(row.map_err(|_| AppError::Internal)?);
    }
    Ok(accounts)
}

/// Deactivate an account.
pub fn deactivate_account(db: &Db, id: &str) -> AppResult<bool> {
    let conn = db.lock().unwrap();
    let count = conn
        .execute(
            "UPDATE accounts SET is_active = 0 WHERE id = ?1",
            params![id],
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

    fn setup_db() -> Db {
        db::connect_and_migrate("sqlite://:memory:").unwrap()
    }

    fn make_account(id: &str) -> AccountRow {
        AccountRow {
            id: id.into(),
            name: "Test Account".into(),
            account_type: "deployer".into(),
            api_key_hash: "hash".into(),
            api_key_prefix: "dd_live_abcd".into(),
            github_login: Some("testuser".into()),
            github_org: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            is_active: true,
        }
    }

    #[test]
    fn insert_and_find_by_prefix() {
        let db = setup_db();
        let account = make_account("acc-1");
        insert_account(&db, &account).unwrap();

        let found = find_by_key_prefix(&db, "dd_live_abcd").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test Account");
    }

    #[test]
    fn deactivate_hides_from_prefix_lookup() {
        let db = setup_db();
        let account = make_account("acc-1");
        insert_account(&db, &account).unwrap();

        deactivate_account(&db, "acc-1").unwrap();

        let found = find_by_key_prefix(&db, "dd_live_abcd").unwrap();
        assert!(found.is_none());
    }
}
