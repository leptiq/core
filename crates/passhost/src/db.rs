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
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
