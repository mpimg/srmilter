use crate::daemon::daemon;
use crate::{
    ClassifyResult, Config, FullEmailClassifier, MailInfo, MailInfoStorage, classify_mail,
};
use clap::Parser;
use mail_parser::{MessageParser, MimeHeaders};
use std::fs;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn cmd_test(
    config: &Config,
    filename: &Path,
    sender: String,
    recipients: Vec<String>,
) -> Result<()> {
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

fn cmd_dump(dump_args: &DumpArgs) -> Result<()> {
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

#[derive(clap::Subcommand)]
enum Command {
    Test {
        filename: PathBuf,
        sender: Option<String>,
        recipients: Option<Vec<String>>,
    },
    Daemon {
        address: Option<String>,
    },
    Dump(DumpArgs),
}

pub type ClassifyFunction = fn(&MailInfo) -> ClassifyResult;

struct FullEmailFnClassifier(ClassifyFunction);

impl FullEmailFnClassifier {
    fn new(f: ClassifyFunction) -> Self {
        Self(f)
    }
}

impl FullEmailClassifier for FullEmailFnClassifier {
    fn classify(&self, mail_info: &MailInfo) -> ClassifyResult {
        self.0(mail_info)
    }
}

pub fn xmain(classify_fn: fn(&MailInfo) -> ClassifyResult) -> Result<()> {
    let cli = Cli::parse();
    let classifier = FullEmailFnClassifier::new(classify_fn);
    let config = Config::builder().full_mail_classifier(&classifier).build();
    match cli.command {
        Command::Test {
            filename,
            sender,
            recipients,
        } => cmd_test(
            &config,
            &filename,
            sender.unwrap_or_default(),
            recipients.unwrap_or_default(),
        ),
        Command::Daemon { address } => {
            daemon(&config, &address.unwrap_or("0.0.0.0:7044".to_string()))
        }
        Command::Dump(dump_args) => cmd_dump(&dump_args),
    }
}
