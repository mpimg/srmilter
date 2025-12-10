#![allow(unused_macros)]

// https://codeberg.org/glts/indymilter
// https://www.postfix.org/MILTER_README.html
// https://github.com/emersion/go-milter/blob/master/milter-protocol.txt
// https://github.com/emersion/go-milter/blob/master/milter-protocol-extras.txt

use clap::Parser;
use nix::libc::c_int;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use socket2::{Domain, Protocol, Socket, Type};
use srmilter::milter::constants::*;
use srmilter::{BufReadExt, ReadExt};
use srmilter::{ClassifyResult, MailInfo, MailInfoStorage};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "systemd")]
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use mail_parser::{MessageParser, MimeHeaders};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod classify;

fn classify_mail(storage: &MailInfoStorage) -> ClassifyResult {
    let r = MessageParser::default().parse(&storage.mail_buffer);
    match r {
        Some(msg) => {
            let mail_info = MailInfo { storage, msg };
            classify::classify(&mail_info)
        }
        None => {
            println!(
                "{}: ACCEPT (because of failure to parse message)",
                storage.id,
            );
            ClassifyResult::Accept
        }
    }
}

fn cmd_test(filename: &Path, sender: String, recipients: Vec<String>) -> Result<()> {
    let storage = MailInfoStorage {
        sender,
        recipients,
        mail_buffer: fs::read(filename)?,
        id: "test".to_string(),
        ..Default::default()
    };
    classify_mail(&storage);
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

fn process_client(mut stream_reader: impl BufRead, mut stream_writer: impl Write) -> Result<()> {
    let mut data_read_buffer: Vec<u8> = Vec::with_capacity(4096);
    let data_write_buffer: Vec<u8> = Vec::with_capacity(64);
    let mut writer = Cursor::new(data_write_buffer);

    let mut connect_macros: HashMap<String, String> = HashMap::new();
    let mut storage = MailInfoStorage::default();

    let mut string_buffer = Vec::<u8>::new();

    loop {
        let len = stream_reader.read_u32_be()?;
        if len > 69632 {
            // 65536+4096 bc. postfix milter8.c : #define MILTER_CHUNK_SIZE 65535 /* body chunk size */
            return Err("received line to long (len} > 69632".into());
        }
        stream_reader.read_bytes(len as usize, &mut data_read_buffer)?;
        let mut data_reader = Cursor::new(data_read_buffer);
        let cmd = data_reader.read_char()?;
        match cmd {
            'O' => {
                // ignored:
                // let version = data_reader.read_u32_be()?;
                // let actions = data_reader.read_u32_be()?;
                // let protocol = data_reader.read_u32_be()?;
                writer.rewind()?;
                writer.write_all(b"O")?;
                writer.write_all(&SMFIF_VERSION.to_be_bytes())?;
                writer.write_all(&SMFIF_QUARANTINE.to_be_bytes())?;
                writer.write_all(
                    &(SMFIP_NOCONNECT
                        | SMFIP_NOHELO
                        | SMFIP_NR_HDR
                        | SMFIP_NOUNKNOWN
                        | SMFIP_NODATA
                        | SMFIP_SKIP
                        | SMFIP_NR_CONN
                        | SMFIP_NR_MAIL
                        | SMFIP_NR_RCPT
                        | SMFIP_NR_EOH
                        | SMFIP_NR_BODY)
                        .to_be_bytes(),
                )?;
                stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                stream_writer.write_all(&writer.get_ref()[0..writer.position() as usize])?;
                stream_writer.flush()?;
            }
            'D' => {
                let for_cmd = data_reader.read_char()?;
                let macro_map = match for_cmd {
                    'C' => &mut connect_macros,
                    _ => &mut storage.macros,
                };
                loop {
                    let name = data_reader.read_zstring(&mut string_buffer)?;
                    if name.is_empty() {
                        break;
                    }
                    let value = data_reader.read_zstring(&mut string_buffer)?;
                    macro_map.insert(name, value);
                }
                // no reply to SMIC_MACRO
            }
            'M' => {
                storage.sender = data_reader.read_zstring_anglestripped(&mut string_buffer)?;
                // possibly followed by more strings (ESMPT arguments)
                // reply disabled with SMFIP_NR_MAIL
            }
            'R' => {
                storage
                    .recipients
                    .push(data_reader.read_zstring_anglestripped(&mut string_buffer)?);
                // reply disabled with SMFIP_NR_RCPT
            }
            'L' => {
                storage
                    .mail_buffer
                    .extend_from_slice(data_reader.read_zbytes(&mut string_buffer)?);
                storage.mail_buffer.extend_from_slice(b": ");
                storage
                    .mail_buffer
                    .extend_from_slice(data_reader.read_zbytes(&mut string_buffer)?);
                storage.mail_buffer.extend_from_slice(b"\r\n");
                // reply disabled with SMFIP_NR_HDR
            }
            'N' => {
                storage.mail_buffer.extend_from_slice(b"\r\n");
                // reply disabled with SMFIP_NR_EOH
            }
            'B' => {
                let mut bdata = Vec::new();
                data_reader.read_to_end(&mut bdata)?;
                storage.mail_buffer.extend_from_slice(&bdata[..]);
                // reply disabled with SMFIP_NR_BODY
            }
            'E' => {
                for (key, value) in &connect_macros {
                    storage.macros.insert(key.clone(), value.clone());
                }
                storage.id = storage
                    .macros
                    .get("i")
                    .map(AsRef::as_ref)
                    .unwrap_or("-")
                    .to_string();
                let result = classify_mail(&storage);
                match result {
                    ClassifyResult::Accept => {
                        writer.rewind()?;
                        writer.write_all(b"a")?; // SMFIR_ACCEPT
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                    }
                    ClassifyResult::Reject => {
                        writer.rewind()?;
                        writer.write_all(b"r")?; // SMFIR_REJECT
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                    }
                    ClassifyResult::Quarantine => {
                        writer.rewind()?;
                        writer.write_all(b"qquarantine test\0")?; // SMFIR_QUARANTINE
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                        writer.rewind()?;
                        writer.write_all(b"a")?; // SMFIR_ACCEPT
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                    }
                };
                stream_writer.flush()?;
                storage = MailInfoStorage::default();
            }
            'Q' => {
                // no reply to SMFIC_QUIT
                break;
            }
            'A' => {
                storage = MailInfoStorage::default();
                // no reply to SMFIC_ABORT
            }
            _ => {
                let mut rest = Vec::new();
                data_reader.read_to_end(&mut rest)?;
                let rest = String::from_utf8_lossy(&rest);
                println!("unimplemented milter command {cmd} rest {rest}");
                todo!("unimplemented");
            }
        }
        data_read_buffer = data_reader.into_inner();
    }
    Ok(())
}

static FLAG_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handlerfunc(signum: c_int) {
    println!("received signal {signum}");
    FLAG_SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handler() {
    unsafe {
        let handler = SigHandler::Handler(handlerfunc);
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        sigaction(Signal::SIGTERM, &action).unwrap();
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        sigaction(Signal::SIGINT, &action).unwrap();
    }
}

fn daemon(address: &str) -> Result<()> {
    #[cfg(feature = "systemd")]
    let listen_socket = match systemd::daemon::listen_fds(false).unwrap().iter().next() {
        Some(fd) => unsafe { Socket::from_raw_fd(fd) },
        None => {
            let address: SocketAddr = address.parse()?;
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&address.into())?;
            socket.listen(1)?;
            socket
        }
    };

    #[cfg(not(feature = "systemd"))]
    let listen_socket = {
        let address: SocketAddr = address.parse()?;
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&address.into())?;
        socket.listen(1)?;
        socket
    };

    install_signal_handler();
    loop {
        let r = listen_socket.accept();
        let (socket, _addr) = match r {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => break,
            _ => r,
        }?;
        // eprintln!("new connection accepted");
        let stream: TcpStream = socket.into();
        let reader = BufReader::new(&stream);
        let writer = BufWriter::new(&stream);
        if let Err(e) = process_client(reader, writer) {
            eprintln!("{e}");
        }
        if FLAG_SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
    }
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

fn xmain() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Test {
            filename,
            sender,
            recipients,
        } => cmd_test(
            &filename,
            sender.unwrap_or_default(),
            recipients.unwrap_or_default(),
        ),
        Command::Daemon { address } => daemon(&address.unwrap_or("0.0.0.0:7044".to_string())),
        Command::Dump(dump_args) => cmd_dump(&dump_args),
    }
}

fn main() -> ExitCode {
    match xmain() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
