mod cli;
mod config;
mod inference;
mod protocol;
mod server;
mod transport;

use anyhow::Result;
use clap::Parser;

fn main() {
    if let Err(error) = run() {
        eprintln!("shellai: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = cli::Cli::parse();
    let mut config = config::Config::load()?;

    match args.command {
        cli::Command::Ask {
            prompt,
            context,
            no_start,
        } => {
            let prompt = prompt.join(" ").trim().to_owned();
            anyhow::ensure!(!prompt.is_empty(), "a request is required");
            let request = protocol::Request::Generate { prompt, context };
            let response = transport::request(&request, !no_start)?;
            if response.ok {
                println!("{}", response.command.unwrap_or_default());
                Ok(())
            } else {
                anyhow::bail!(response.error.unwrap_or_else(|| "request failed".into()))
            }
        }
        cli::Command::Server {
            model_ttl,
            background_child: _,
        } => {
            if let Some(ttl) = model_ttl {
                config.model_ttl_seconds = ttl;
            }
            server::run(config)
        }
        cli::Command::Status => {
            let response = transport::request(&protocol::Request::Status, false)?;
            if response.ok {
                println!(
                    "server: running\nmodel: {}",
                    if response.model_loaded {
                        "loaded"
                    } else {
                        "unloaded"
                    }
                );
                Ok(())
            } else {
                anyhow::bail!(response.error.unwrap_or_else(|| "status failed".into()))
            }
        }
        cli::Command::Stop => {
            let response = transport::request(&protocol::Request::Shutdown, false)?;
            anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
            println!("server stopped");
            Ok(())
        }
        cli::Command::Download => {
            let path = inference::resolve_model_path(&config)?;
            println!("{}", path.display());
            Ok(())
        }
        cli::Command::Config { init } => {
            if init {
                let path = config::Config::write_default_if_missing()?;
                println!("{}", path.display());
            } else {
                println!("{}", config::Config::path()?.display());
            }
            Ok(())
        }
        cli::Command::Plugin => {
            print!("{}", include_str!("../shellai.plugin.zsh"));
            Ok(())
        }
    }
}
