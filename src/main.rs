// https://codeberg.org/glts/indymilter
// https://www.postfix.org/MILTER_README.html
// https://github.com/emersion/go-milter/blob/master/milter-protocol.txt
// https://github.com/emersion/go-milter/blob/master/milter-protocol-extras.txt

use clap::Parser;
use lazy_regex::*;
use nix::libc::c_int;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use socket2::{Domain, Protocol, Socket, Type};
use std::borrow::Cow::Borrowed;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read, Seek, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use mail_parser::{HeaderName, MessageParser};

#[allow(dead_code)]
mod constants {
    pub const SMFIF_VERSION: u32 = 6;

    // actions
    pub const SMFIF_ADDHDRS: u32 = 0x00000001;
    pub const SMFIF_CHGBODY: u32 = 0x00000002;
    pub const SMFIF_ADDRCPT: u32 = 0x00000004;
    pub const SMFIF_DELRCPT: u32 = 0x00000008;
    pub const SMFIF_CHGHDRS: u32 = 0x00000010;
    pub const SMFIF_QUARANTINE: u32 = 0x00000020;
    pub const SMFIF_CHGFROM: u32 = 0x00000040;
    pub const SMFIF_ADDRCPT_PAR: u32 = 0x00000080;
    pub const SMFIF_SETSYMLIST: u32 = 0x00000100;

    // protocol flags

    pub const SMFIP_NOCONNECT: u32 = 0x00000001;
    pub const SMFIP_NOHELO: u32 = 0x00000002;
    pub const SMFIP_NOMAIL: u32 = 0x00000004;
    pub const SMFIP_NORCPT: u32 = 0x00000008;
    pub const SMFIP_NOBODY: u32 = 0x00000010;
    pub const SMFIP_NOHDRS: u32 = 0x00000020;
    pub const SMFIP_NOEOH: u32 = 0x00000040;

    pub const SMFIP_NR_HDR: u32 = 0x00000080;
    pub const SMFIP_NOUNKNOWN: u32 = 0x00000100;
    pub const SMFIP_NODATA: u32 = 0x00000200;
    pub const SMFIP_SKIP: u32 = 0x00000400;
    pub const SMFIP_RCPT_REJ: u32 = 0x00000800;
    pub const SMFIP_NR_CONN: u32 = 0x00001000;
    pub const SMFIP_NR_HELO: u32 = 0x00002000;
    pub const SMFIP_NR_MAIL: u32 = 0x00004000;
    pub const SMFIP_NR_RCPT: u32 = 0x00008000;
    pub const SMFIP_NR_DATA: u32 = 0x00010000;
    pub const SMFIP_NR_UNKN: u32 = 0x00020000;
    pub const SMFIP_NR_EOH: u32 = 0x00040000;
    pub const SMFIP_NR_BODY: u32 = 0x00080000;
    pub const SMFIP_HDR_LEADSPC: u32 = 0x00100000;
    pub const SMFIP_MDS_256K: u32 = 0x10000000;
    pub const SMFIP_MDS_1M: u32 = 0x20000000;
}

use constants::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn to_boxed_error<E: std::error::Error + 'static>(error: E) -> Box<dyn std::error::Error> {
    Box::new(error)
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn read_char(reader: &mut impl Read) -> Result<char> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0] as char)
}

fn read_bytes(reader: &mut impl Read, len: usize, data: &mut Vec<u8>) -> Result<()> {
    data.resize(len, 0u8);
    reader.read_exact(data).map_err(to_boxed_error)
}

fn vec_trim_zero(input: &[u8]) -> &[u8] {
    if let Some(pos) = input.iter().rposition(|&x| x != 0) {
        &input[0..=pos]
    } else {
        input
    }
}

fn read_zbytes<'a>(reader: &mut impl BufRead, buffer: &'a mut Vec<u8>) -> Result<&'a [u8]> {
    buffer.clear();
    reader.read_until(b'\0', buffer)?;
    Ok(vec_trim_zero(buffer))
}

fn read_zstring(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> Result<String> {
    Ok(String::from_utf8_lossy(read_zbytes(reader, buffer)?).to_string())
}

#[allow(dead_code)]
#[derive(Debug)]
enum ClassifyResult {
    Accept,
    Reject,
    Quarantine,
}

#[derive(Default)]
struct MailInfo {
    sender: String,
    recipients: Vec<String>,
    macros: HashMap<String, String>,
    mail_buffer: Vec<u8>,
}

#[allow(unused_variables)]
fn classify_parsed_mail(mail_info: &MailInfo, msg: &mail_parser::Message) -> ClassifyResult {
    let from_address = msg
        .header(HeaderName::From)
        .and_then(|v| v.as_address())
        .and_then(|v| v.as_list())
        .and_then(|v| v.first())
        .and_then(|v| v.address())
        .unwrap_or("");
    let subject = msg
        .header(HeaderName::Subject)
        .and_then(|v| v.as_text())
        .unwrap_or("");
    let sender = &mail_info.sender;
    let recipients = &mail_info.recipients;

    include!("srmilter.classify.rs");

    ClassifyResult::Accept
}

fn classify_mail(mail_info: &MailInfo) -> ClassifyResult {
    let r = MessageParser::default().parse(&mail_info.mail_buffer);
    match r {
        Some(msg) => classify_parsed_mail(mail_info, &msg),
        None => {
            eprintln!("failed to parse message!");
            ClassifyResult::Accept
        }
    }
}

fn cmd_test(filename: &Path, sender: String, recipients: Vec<String>) -> Result<()> {
    let mail_info = MailInfo {
        sender,
        recipients,
        mail_buffer: fs::read(filename)?,
        ..Default::default()
    };
    let result = classify_mail(&mail_info);
    dbg!(result);
    Ok(())
}

fn process_client(mut stream_reader: impl BufRead, mut stream_writer: impl Write) -> Result<()> {
    let mut data_read_buffer: Vec<u8> = Vec::with_capacity(4096);
    let data_write_buffer: Vec<u8> = Vec::with_capacity(64);
    let mut writer = Cursor::new(data_write_buffer);

    let mut connect_macros: HashMap<String, String> = HashMap::new();
    let mut mail_info = MailInfo::default();

    let mut string_buffer = Vec::<u8>::new();

    loop {
        let len = read_u32(&mut stream_reader)?;
        if len > 69632 {
            // 65536+4096 bc. postfix milter8.c : #define MILTER_CHUNK_SIZE 65535 /* body chunk size */
            return Err("received line to long (len} > 69632".into());
        }
        read_bytes(&mut stream_reader, len as usize, &mut data_read_buffer)?;
        let mut data_reader = Cursor::new(data_read_buffer);
        let cmd = read_char(&mut data_reader)?;
        match cmd {
            'O' => {
                // ignored:
                // let version = read_u32(&mut data_reader)?;
                // let actions = read_u32(&mut data_reader)?;
                // let protocol = read_u32(&mut data_reader)?;
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
                let for_cmd = read_char(&mut data_reader)?;
                let macro_map = match for_cmd {
                    'C' => &mut connect_macros,
                    _ => &mut mail_info.macros,
                };
                loop {
                    let name = read_zstring(&mut data_reader, &mut string_buffer)?;
                    if name.is_empty() {
                        break;
                    }
                    let value = read_zstring(&mut data_reader, &mut string_buffer)?;
                    macro_map.insert(name, value);
                }
                // no reply to SMIC_MACRO
            }
            'M' => {
                mail_info.sender = read_zstring(&mut data_reader, &mut string_buffer)?;
                // possibly followed by more strings (ESMPT arguments)
                // reply disabled with SMFIP_NR_MAIL
            }
            'R' => {
                mail_info
                    .recipients
                    .push(read_zstring(&mut data_reader, &mut string_buffer)?);
                // reply disabled with SMFIP_NR_RCPT
            }
            'L' => {
                mail_info
                    .mail_buffer
                    .extend_from_slice(read_zbytes(&mut data_reader, &mut string_buffer)?);
                mail_info.mail_buffer.extend_from_slice(b": ");
                mail_info
                    .mail_buffer
                    .extend_from_slice(read_zbytes(&mut data_reader, &mut string_buffer)?);
                mail_info.mail_buffer.extend_from_slice(b"\r\n");
                // reply disabled with SMFIP_NR_HDR
            }
            'N' => {
                mail_info.mail_buffer.extend_from_slice(b"\r\n");
                // reply disabled with SMFIP_NR_EOH
            }
            'B' => {
                let mut bdata = Vec::new();
                data_reader.read_to_end(&mut bdata)?;
                mail_info.mail_buffer.extend_from_slice(&bdata[..]);
                // reply disabled with SMFIP_NR_BODY
            }
            'E' => {
                for (key, value) in &connect_macros {
                    mail_info.macros.insert(key.clone(), value.clone());
                }
                let result = classify_mail(&mail_info);
                let queue_id = mail_info.macros.get("i").map(AsRef::as_ref).unwrap_or("-");
                match result {
                    ClassifyResult::Accept => {
                        writer.rewind()?;
                        writer.write_all(b"a")?; // SMFIR_ACCEPT
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                        println!("{queue_id}: accept");
                    }
                    ClassifyResult::Reject => {
                        writer.rewind()?;
                        writer.write_all(b"r")?; // SMFIR_REJECT
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                        println!("{queue_id}: reject");
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
                        println!("{queue_id}: quarantine");
                    }
                };
                stream_writer.flush()?;
                mail_info = MailInfo::default();
            }
            'Q' => {
                // no reply to SMFIC_QUIT
                break;
            }
            'A' => {
                mail_info = MailInfo::default();
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

/************ tests **************/

#[test]
fn test_read_bytes() {
    let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut reader = &input[..];
    let mut output = Vec::<u8>::new();
    read_bytes(&mut reader, 26usize, &mut output).unwrap();
    assert_eq!(output, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(reader, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let cap = output.capacity();

    let input = b"1234";
    let mut reader = &input[..];
    read_bytes(&mut reader, 2usize, &mut output).unwrap();
    assert_eq!(output, b"12");
    assert_eq!(reader, b"34");
    assert!(output.capacity() >= cap);
}

#[test]
fn test_write_cursor() {
    let write_buffer: Vec<u8> = Vec::with_capacity(0);
    let mut writer = Cursor::new(write_buffer);

    writer.write_all(b"abcdefghijklmnopqrstuvwxyz").unwrap();
    let data = &writer.get_ref()[0..writer.position() as usize];
    assert_eq!(data, b"abcdefghijklmnopqrstuvwxyz");
    let cap = writer.get_ref().capacity();

    writer.rewind().unwrap();
    writer.write_all(b"123456").unwrap();
    let data = &writer.get_ref()[0..writer.position() as usize];
    assert_eq!(data, b"123456");

    assert!(writer.get_ref().capacity() >= cap);
}

#[test]
fn test_cli() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

#[test]
fn test_vec_trim() {
    let input: [u8; 0] = [];
    assert_eq!(vec_trim_zero(&input), input);
    let input: [u8; 3] = [1, 2, 3];
    assert_eq!(vec_trim_zero(&input), input);
    let input: [u8; 6] = [1, 2, 3, 0, 0, 0];
    assert_eq!(vec_trim_zero(&input), [1, 2, 3]);
    let input: [u8; 7] = [1, 2, 3, 0, 0, 0, 5];
    assert_eq!(vec_trim_zero(&input), [1, 2, 3, 0, 0, 0, 5]);
}

#[test]
fn test_read_cstr() {
    let input = b"Test1\0Test2\0Test3";
    let mut reader = Cursor::new(&input);
    let mut buffer: Vec<u8> = Vec::new();
    assert_eq!(read_zstring(&mut reader, &mut buffer).unwrap(), "Test1");
    assert_eq!(read_zstring(&mut reader, &mut buffer).unwrap(), "Test2");
    assert_eq!(read_zstring(&mut reader, &mut buffer).unwrap(), "Test3");
    assert_eq!(read_zstring(&mut reader, &mut buffer).unwrap(), "");
}
