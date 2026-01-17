use crate::daemon::daemon;
use crate::{Config, MailInfoStorage, classify_mail};
use clap::Parser;
use mail_parser::{MessageParser, MimeHeaders};
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

fn cmd_dump(dump_args: &DumpArgs) -> Result<(), Box<dyn Error>> {
    let (dump_header, dump_body) = match (dump_args.header, dump_args.body) {
        (false, false) => (true, true),
        (dump_header, dump_body) => (dump_header, dump_body),
    };
    let dump_html = dump_args.dump_html;
    let filename = &dump_args.filename;
    let mail_buffer = fs::read(filename)?;
    let r = MessageParser::default().parse(&mail_buffer);
    match r {
        Some(msg) => {
            if dump_header && let Some(part) = msg.parts.first() {
                for h in &part.headers {
                    println!("{}: {:?}", h.name, &h.value);
                }
            }
            if dump_body {
                for part in msg.parts {
                    let (content_type, content_subtype) = {
                        match part.content_type() {
                            Some(c) => (c.ctype(), c.subtype().unwrap_or("")),
                            None => ("???", "???"),
                        }
                    };
                    println!(
                        "==================================== {}/{}",
                        content_type, content_subtype
                    );
                    if part.is_content_type("text", "plain") {
                        if let Some(text) = part.text_contents() {
                            println!("{}", text.trim());
                        }
                    } else if dump_html
                        && part.is_content_type("text", "html")
                        && let Some(text) = part.text_contents()
                    {
                        let md = html2md::rewrite_html(text, false);
                        println!("{}", md);
                    }
                }
            }
            Ok(())
        }
        None => Err("parse error".into()),
    }
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
    #[arg(long = "fork", default_value_t = 0, hide_default_value = true)]
    pub fork_max: u16,
    #[arg(long = "threads", default_value_t = 0, hide_default_value = true)]
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
    Dump(DumpArgs),
}

/// Main entry point for the milter CLI.
///
/// Parses command-line arguments and runs the appropriate subcommand:
///
/// - `daemon [address] [--fork N] [--threads N] [--truncate N]` - Run the milter server
///   (default address: `0.0.0.0:7044`)
/// - `test <file> [sender] [recipients...]` - Test the classifier against an `.eml` file
/// - `dump <file> [-H] [-b] [--html]` - Dump parsed email headers and/or body
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
        Command::Daemon(args) => {
            if args.fork_max > 0 && args.threads_max > 0 {
                return Err("--fork and --threads are mutually exclusive".into());
            }
            if args.fork_max > 0 && !config.fork_mode_enabled {
                return Err(
                    "--fork mode not available: Needs to be opted in by main milter program."
                        .into(),
                );
            }
            daemon(
                config,
                &args.address,
                args.fork_max,
                args.threads_max,
                args.truncate,
            )
        }
        Command::Dump(dump_args) => cmd_dump(&dump_args),
    }
}
