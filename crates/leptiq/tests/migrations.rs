//! Core and product migrations share one `_sqlx_migrations` table with
//! disjoint version ranges.

#[tokio::test]
async fn core_and_product_migrations_apply_and_rerun() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = leptiq::Config::default();
    config.database_url = std::env::var("LEPTIQ_TEST_DATABASE_URL")
        .unwrap_or_else(|_| format!("sqlite://{}/m.db?mode=rwc", dir.path().display()));
    config.data_dir = dir.path().join("data").display().to_string();

    let state = leptiq::build_state(config.clone()).await.unwrap();
    let versions: Vec<(i64,)> =
        sqlx::query_as("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&state.db)
            .await
            .unwrap();
    let versions: Vec<i64> = versions.into_iter().map(|v| v.0).collect();
    assert!(versions.contains(&1), "core migrations: {versions:?}");
    assert!(versions.contains(&1000), "pass migrations: {versions:?}");

    // A second start (core migrator sees pass rows and vice versa) is a no-op.
    drop(state);
    let state = leptiq::build_state(config).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(n as usize, versions.len());
}
