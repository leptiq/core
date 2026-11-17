use clap::{Parser, Subcommand};
use leptiq::Config;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "passhost",
    version,
    about = "Self-hostable server for Proton Pass clients"
)]
struct Cli {
    /// Path to a TOML config file (env vars prefixed PASSHOST_ override it).
    #[arg(short, long, env = "PASSHOST_CONFIG", default_value = "passhost.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP server (default).
    Serve,
    /// Run database migrations and exit.
    Migrate,
    /// Administrative commands.
    #[command(subcommand)]
    Admin(leptiq::admin::AdminCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    match cli.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            leptiq::build_state(config).await?;
            tracing::info!("migrations applied");
        }
        Command::Admin(cmd) => {
            let state = leptiq::build_state(config).await?;
            leptiq::admin::run(&state, cmd).await?;
        }
        Command::Serve => {
            let bind = config.bind.clone();
            let state = leptiq::build_state(config).await?;
            state.spawn_background_tasks();
            let router = leptiq::build_router(state);
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("listening on {bind}");
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
