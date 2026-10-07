mod cli;
mod commands;
mod logging;
mod reports;
mod server;

#[tokio::main]
#[cfg_attr(feature = "profiling", hotpath::main)]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}

#[cfg(test)]
mod tests;
