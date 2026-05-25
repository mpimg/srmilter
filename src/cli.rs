use crate::daemon::daemon;
use crate::{Config, MailInfoStorage, classify_mail};
use clap::Parser;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn cmd_test(
    config: &Config,
    filename: &Path,
    sender: String,
    recipients: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let storage = MailInfoStorage {
        sender,
        recipients,
        mail_buffer: fs::read(filename)?,
        id: "test".to_string(),
        ..Default::default()
    };
    classify_mail(config, &storage);
    Ok(())
}

#[derive(clap::Parser)]
#[command()]
struct Cli {
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args, Debug)]
struct DumpArgs {
    filename: PathBuf,
    #[arg(short = 'H', long)]
    header: bool,
    #[arg(short, long)]
    body: bool,
    #[arg(long = "html")]
    dump_html: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct DaemonArgs {
    #[arg(default_value = "0.0.0.0:7044")]
    pub address: String,
    #[arg(long = "threads", default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..))]
    pub threads_max: u16,
    #[arg(long = "truncate", default_value_t = usize::MAX, hide_default_value = true, value_name = "BYTES")]
    pub truncate: usize,
}

#[derive(clap::Subcommand)]
enum Command {
    Test {
        filename: PathBuf,
        sender: Option<String>,
        recipients: Option<Vec<String>>,
    },
    Daemon(DaemonArgs),
}

/// Main entry point for the milter CLI.
///
/// Parses command-line arguments and runs the appropriate subcommand:
///
/// - `daemon [address] [--threads N] [--truncate N]` - Run the milter server
///   (default address: `0.0.0.0:7044`)
/// - `test <file> [sender] [recipients...]` - Test the classifier against an `.eml` file
///
/// # Example
///
/// ```ignore
/// fn main() -> impl std::process::Termination {
///     let classifier = FullEmailFnClassifier::new(my_classifier);
///     let config = Config::builder()
///         .full_mail_classifier(&classifier)
///         .build();
///     srmilter::cli::cli(&config)
/// }
/// ```
pub fn cli(config: &Config) -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Test {
            filename,
            sender,
            recipients,
        } => cmd_test(
            config,
            &filename,
            sender.unwrap_or_default(),
            recipients.unwrap_or_default(),
        ),
        Command::Daemon(args) => daemon(config, &args),
    }
}
