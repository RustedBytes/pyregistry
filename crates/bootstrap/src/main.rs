mod cli;
mod commands;
mod logging;
mod reports;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}

#[cfg(test)]
mod tests;
