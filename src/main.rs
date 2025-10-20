use clap::{Parser, Subcommand};
use std::error::Error;

#[derive(Parser)]
#[command(name = "rift")]
#[command(about = "Distributed file transfer tool", long_about = None)]
#[command(version)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file or folder
    Send {
        /// Path to the file or folder to send
        file_path: String,
    },
    /// Receive a file or folder
    Receive {
        /// Optional 6-digit shared key (will prompt if not provided)
        key: Option<u32>,
    },
    /// Run as a relay server
    Relay {
        /// Port to bind to (default: 8080)
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // Configure logging based on verbose flag
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
        log::info!("Verbose logging enabled");
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    match cli.command {
        Commands::Send { file_path } => {
            rift::commands::send::run(&file_path).await?;
        }
        Commands::Receive { key } => {
            rift::commands::receive::run(key).await?;
        }
        Commands::Relay { port } => {
            rift::commands::relay::run(port).await?;
        }
    }

    Ok(())
}
