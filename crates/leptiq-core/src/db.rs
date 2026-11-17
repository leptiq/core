//! Database access. One SQL dialect for both SQLite and Postgres: TEXT and
//! BIGINT columns only, `$N` placeholders (SQLite accepts them too).

use sqlx::AnyPool;
use sqlx::any::{AnyPoolOptions, install_default_drivers};

pub type Pool = AnyPool;
pub type Tx<'a> = sqlx::Transaction<'a, sqlx::Any>;

pub async fn connect(url: &str) -> anyhow::Result<Pool> {
    install_default_drivers();
    let is_sqlite = url.starts_with("sqlite:");
    let pool = AnyPoolOptions::new()
        .max_connections(if is_sqlite { 1 } else { 16 })
        // SQLite uses a single connection: a handler must never hold a
        // connection while acquiring another. A short timeout surfaces bugs.
        .acquire_timeout(std::time::Duration::from_secs(if is_sqlite { 10 } else { 30 }))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if is_sqlite {
                    use sqlx::Executor;
                    conn.execute("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")
                        .await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await?;
    Ok(pool)
}

/// Core's own migrations (accounts, sessions, keys, events...).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Runs core's migrations, then each product's, in order. All migrators share
/// one `_sqlx_migrations` table with disjoint version ranges, so each one
/// ignores the others' rows.
pub async fn migrate(
    pool: &Pool,
    products: &[std::sync::Arc<dyn crate::Product>],
) -> anyhow::Result<()> {
    run_migrator(pool, &MIGRATOR).await?;
    for product in products {
        run_migrator(pool, product.migrator()).await?;
    }
    Ok(())
}

async fn run_migrator(pool: &Pool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<()> {
    let mut m = sqlx::migrate::Migrator {
        migrations: migrator.migrations.clone(),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    m.set_ignore_missing(true);
    m.run(pool).await?;
    Ok(())
}

/// `format!` for SQL built only from compile-time column lists (never user input).
#[macro_export]
macro_rules! sql {
    ($($t:tt)*) => { sqlx::AssertSqlSafe(format!($($t)*)) };
}

/// Next value of a named counter (atomic on both backends).
pub async fn next_counter(conn: &mut sqlx::AnyConnection, name: &str) -> Result<i64, sqlx::Error> {
    let (v,): (i64,) = sqlx::query_as(
        "INSERT INTO counters (name, value) VALUES ($1, 1) \
         ON CONFLICT (name) DO UPDATE SET value = counters.value + 1 RETURNING value",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    Ok(v)
}
