#![forbid(unsafe_code)]

use clap::Parser as _;
use tinylayer_wallet::{Cli, run};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    if let Err(error) = run(cli).await {
        if json {
            eprintln!("{}", serde_json::json!({ "error": format!("{error:#}") }));
        } else {
            eprintln!("error: {error:#}");
        }
        std::process::exit(1);
    }
}
