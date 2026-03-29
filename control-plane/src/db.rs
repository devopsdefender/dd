use rusqlite::Connection;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

pub fn connect_and_migrate(url: &str) -> Result<Db, rusqlite::Error> {
    // url is like "sqlite://foo.db?mode=rwc" -- extract path
    let path = url
        .strip_prefix("sqlite://")
        .unwrap_or(url)
        .split('?')
        .next()
        .unwrap_or("devopsdefender.db");

    let conn = if path == ":memory:" {
        Connection::open_in_memory()?
    } else {
        Connection::open(path)?
    };
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(include_str!("../migrations/0001_init.sql"))?;
    conn.execute_batch(include_str!("../migrations/0002_measurer_trust.sql"))?;
    conn.execute_batch(include_str!("../migrations/0003_provider_skus.sql"))?;
    conn.execute_batch(include_str!(
        "../migrations/0004_agent_attestation_token.sql"
    ))?;
    conn.execute_batch(include_str!("../migrations/0005_app_ownership.sql"))?;
    Ok(Arc::new(Mutex::new(conn)))
}
