//! `passhost admin ...` commands.

use clap::Subcommand;

use leptiq_core::{
    AppState,
    util::{new_token, now},
};

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Create a single-use signup invite code (for `signup = "invite"`).
    Invite,
    /// List users.
    Users,
    /// Grant or revoke admin rights.
    SetAdmin {
        username: String,
        #[arg(long, default_value_t = true)]
        admin: bool,
    },
    /// Delete a user and all their data.
    DeleteUser { username: String },
    /// Print the SRP modulus in use.
    Modulus,
}

pub async fn run(state: &AppState, cmd: AdminCommand) -> anyhow::Result<()> {
    match cmd {
        AdminCommand::Invite => {
            let code = new_token(24);
            sqlx::query("INSERT INTO signup_invites (code, created) VALUES ($1, $2)")
                .bind(&code)
                .bind(now())
                .execute(&state.db)
                .await?;
            println!("{code}");
        }
        AdminCommand::Users => {
            let rows: Vec<(String, String, i64)> =
                sqlx::query_as("SELECT id, name, is_admin FROM users ORDER BY created")
                    .fetch_all(&state.db)
                    .await?;
            for (id, name, admin) in rows {
                println!("{name}\t{id}{}", if admin != 0 { "\tadmin" } else { "" });
            }
        }
        AdminCommand::SetAdmin { username, admin } => {
            let res = sqlx::query("UPDATE users SET is_admin = $1 WHERE name = $2")
                .bind(admin as i64)
                .bind(username.to_lowercase())
                .execute(&state.db)
                .await?;
            anyhow::ensure!(res.rows_affected() == 1, "no such user");
        }
        AdminCommand::DeleteUser { username } => {
            let row: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE name = $1")
                .bind(username.to_lowercase())
                .fetch_optional(&state.db)
                .await?;
            let (user_id,) = row.ok_or_else(|| anyhow::anyhow!("no such user"))?;
            for product in &state.products {
                product
                    .on_user_deleted(state, &user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            }
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(&user_id)
                .execute(&state.db)
                .await?;
        }
        AdminCommand::Modulus => println!("{}", state.modulus.signed),
    }
    Ok(())
}
