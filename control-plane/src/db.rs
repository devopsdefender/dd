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
    Ok(Arc::new(Mutex::new(conn)))
}

/// Tables included in state export/import, ordered to respect foreign key constraints.
const EXPORTABLE_TABLES: &[&str] = &[
    "agents",
    "agent_control_credentials",
    "deployments",
    "app_health_checks",
    "services",
    "apps",
    "app_versions",
    "accounts",
    "settings",
    "trusted_mrtds",
    // admin_sessions are intentionally excluded — they are ephemeral
];

/// Export all table data as a map of table_name → Vec<Row>, where each row is
/// a map of column_name → JSON value.
pub fn export_all_tables(
    db: &Db,
) -> Result<serde_json::Map<String, serde_json::Value>, rusqlite::Error> {
    let conn = db.lock().unwrap();
    let mut tables = serde_json::Map::new();

    for &table in EXPORTABLE_TABLES {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table}"))?;
        let col_count = stmt.column_count();
        let col_names: Vec<String> = (0..col_count)
            .map(|i| stmt.column_name(i).unwrap().to_string())
            .collect();

        let rows = stmt.query_map([], |row| {
            let mut obj = serde_json::Map::new();
            for (i, name) in col_names.iter().enumerate() {
                let val: rusqlite::types::Value = row.get(i)?;
                let json_val = match val {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(n) => serde_json::Value::Number(n.into()),
                    rusqlite::types::Value::Real(f) => serde_json::Value::Number(
                        serde_json::Number::from_f64(f).unwrap_or_else(|| 0.into()),
                    ),
                    rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
                    rusqlite::types::Value::Blob(b) => serde_json::Value::String(
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b),
                    ),
                };
                obj.insert(name.clone(), json_val);
            }
            Ok(serde_json::Value::Object(obj))
        })?;

        let mut table_rows = Vec::new();
        for row in rows {
            table_rows.push(row?);
        }
        tables.insert(table.to_string(), serde_json::Value::Array(table_rows));
    }

    Ok(tables)
}

/// Import table data from a state bundle, replacing all existing data.
/// Tables are cleared and repopulated in foreign-key-safe order.
pub fn import_all_tables(
    db: &Db,
    tables: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let conn = db.lock().unwrap();

    // Temporarily disable FK checks during import
    conn.execute_batch("PRAGMA foreign_keys=OFF;")
        .map_err(|e| format!("disable FK: {e}"))?;

    // Clear tables in reverse order (respect FK deps)
    for &table in EXPORTABLE_TABLES.iter().rev() {
        conn.execute(&format!("DELETE FROM {table}"), [])
            .map_err(|e| format!("clear {table}: {e}"))?;
    }

    // Insert rows in forward order
    for &table in EXPORTABLE_TABLES {
        let rows = match tables.get(table) {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => continue,
        };

        for row_val in rows {
            let obj = match row_val.as_object() {
                Some(o) => o,
                None => continue,
            };

            if obj.is_empty() {
                continue;
            }

            let cols: Vec<&String> = obj.keys().collect();
            let col_list = cols
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let placeholders = (1..=cols.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!("INSERT INTO {table} ({col_list}) VALUES ({placeholders})");

            let values: Vec<Box<dyn rusqlite::types::ToSql>> = cols
                .iter()
                .map(|col| -> Box<dyn rusqlite::types::ToSql> {
                    match &obj[col.as_str()] {
                        serde_json::Value::Null => Box::new(Option::<String>::None),
                        serde_json::Value::Bool(b) => Box::new(*b as i64),
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64() {
                                Box::new(i)
                            } else if let Some(f) = n.as_f64() {
                                Box::new(f)
                            } else {
                                Box::new(Option::<String>::None)
                            }
                        }
                        serde_json::Value::String(s) => Box::new(s.clone()),
                        other => Box::new(other.to_string()),
                    }
                })
                .collect();

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                values.iter().map(|v| v.as_ref()).collect();

            conn.execute(&sql, param_refs.as_slice())
                .map_err(|e| format!("insert into {table}: {e}"))?;
        }
    }

    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|e| format!("re-enable FK: {e}"))?;

    Ok(())
}
