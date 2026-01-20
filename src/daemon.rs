use crate::cli::DaemonArgs;
use crate::milter::constants::*;
use crate::reader_extention::{BufReadExt as _, ReadExt as _};
use crate::{ClassifyResult, Config, MailInfoStorage, classify_mail};
use nix::libc::c_int;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pause};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, BufReader, BufWriter, Cursor, Read as _, Seek as _, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "systemd")]
use std::os::fd::FromRawFd as _;
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

// https://codeberg.org/glts/indymilter
// https://www.postfix.org/MILTER_README.html
// https://github.com/emersion/go-milter/blob/master/milter-protocol.txt
// https://github.com/emersion/go-milter/blob/master/milter-protocol-extras.txt

static FLAG_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static CHILDREN_CNT: AtomicU16 = AtomicU16::new(0);

fn process_client(
    config: &Config,
    mut stream_reader: impl BufRead,
    mut stream_writer: impl Write,
    truncate: usize,
) -> Result<(), Box<dyn Error>> {
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
                let mut protocol = SMFIP_NOCONNECT
                    | SMFIP_NOHELO
                    | SMFIP_NR_HDR
                    | SMFIP_NOUNKNOWN
                    | SMFIP_NODATA
                    | SMFIP_SKIP
                    | SMFIP_NR_CONN
                    | SMFIP_NR_MAIL
                    | SMFIP_NR_RCPT
                    | SMFIP_NR_EOH;
                if truncate == 0 {
                    protocol |= SMFIP_NOBODY
                }
                if truncate == usize::MAX {
                    protocol |= SMFIP_NR_BODY
                }
                writer.write_all(&protocol.to_be_bytes())?;
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
                let buffer_space = truncate - storage.mail_buffer.len();
                let pos = data_reader.position() as usize;
                let data = &data_reader.get_ref()[pos..];
                if data.len() <= buffer_space {
                    storage.mail_buffer.extend_from_slice(data);
                } else {
                    storage
                        .mail_buffer
                        .extend_from_slice(&data[0..buffer_space]);
                }
                if truncate == usize::MAX {
                    // reply disabled with SMFIP_NR_BODY
                } else {
                    if storage.mail_buffer.len() < truncate {
                        // continue
                        writer.rewind()?;
                        writer.write_all(b"c")?; // SMFIR_CONTINUE
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                    } else {
                        // skip
                        writer.rewind()?;
                        writer.write_all(b"s")?; // SMFIR_SKIP
                        stream_writer.write_all(&((writer.position() as u32).to_be_bytes()))?;
                        stream_writer
                            .write_all(&writer.get_ref()[0..writer.position() as usize])?;
                    }
                    stream_writer.flush()?;
                }
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
                let result = classify_mail(config, &storage);
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
                        writer.write_all(b"qmilter\0")?; // SMFIR_QUARANTINE
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
                eprintln!("unimplemented milter command {cmd} rest {rest}");
                todo!("unimplemented");
            }
        }
        data_read_buffer = data_reader.into_inner();
    }
    Ok(())
}

extern "C" fn handlerfunc(signum: c_int) {
    eprintln!("received signal {signum}");
    FLAG_SHUTDOWN.store(true, Ordering::Relaxed);
}

extern "C" fn handlerfunc_child(_signum: c_int) {
    if let WaitStatus::Exited(_pid, _exit_code) =
        waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)).unwrap()
        && CHILDREN_CNT.fetch_sub(1, Ordering::Relaxed) == 0
    {
        panic!("children underflow");
    }
}

fn install_signal_handler() {
    unsafe {
        let handler = SigHandler::Handler(handlerfunc);
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        sigaction(Signal::SIGTERM, &action).unwrap();
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
        sigaction(Signal::SIGINT, &action).unwrap();
        let handler = SigHandler::Handler(handlerfunc_child);
        let action = SigAction::new(handler, SaFlags::SA_NOCLDSTOP, SigSet::empty());
        sigaction(Signal::SIGCHLD, &action).unwrap();
    }
}

pub fn daemon(config: &Config, args: &DaemonArgs) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "systemd")]
    let listen_socket = match systemd::daemon::listen_fds(false).unwrap().iter().next() {
        Some(fd) => unsafe { Socket::from_raw_fd(fd) },
        None => {
            let address: SocketAddr = args.address.parse()?;
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&address.into())?;
            socket.listen(1)?;
            socket
        }
    };

    #[cfg(not(feature = "systemd"))]
    let listen_socket = {
        let address: SocketAddr = args.address.parse()?;
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&address.into())?;
        socket.listen(1)?;
        socket
    };

    if args.fork_max > 0 && args.threads_max > 0 {
        return Err("Cannot use both fork and thread modes simultaneously".into());
    }

    let thread_state: Option<Arc<(Mutex<u16>, Condvar)>> = if args.threads_max > 0 {
        Some(Arc::new((Mutex::new(0), Condvar::new())))
    } else {
        None
    };

    install_signal_handler();
    loop {
        if args.fork_max > 0 {
            while CHILDREN_CNT.load(Ordering::Relaxed) >= args.fork_max {
                pause()
            }
        } else if let Some(ref state) = thread_state {
            let (lock, cvar) = state.as_ref();
            let mut count = lock.lock().unwrap();
            while *count >= args.threads_max {
                count = cvar.wait(count).unwrap();
            }
        }
        match listen_socket.accept() {
            Ok((socket, _addr)) => {
                if args.fork_max > 0 {
                    match unsafe { fork() } {
                        Ok(ForkResult::Parent { .. }) => {
                            CHILDREN_CNT.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(ForkResult::Child) => {
                            drop(listen_socket);
                            let stream: TcpStream = socket.into();
                            let reader = BufReader::new(&stream);
                            let writer = BufWriter::new(&stream);
                            match process_client(config, reader, writer, args.truncate) {
                                Ok(_) => exit(0),
                                Err(e) => {
                                    eprintln!("{e}");
                                    exit(1)
                                }
                            }
                        }
                        Err(e) => eprintln!("fork: {e}"),
                    }
                } else if args.threads_max > 0 {
                    let state_clone = thread_state.as_ref().unwrap().clone();

                    // Increment thread count
                    {
                        let (lock, _) = state_clone.as_ref();
                        let mut count = lock.lock().unwrap();
                        *count += 1;
                    }

                    let stream: TcpStream = socket.into();

                    // Extract Arc from config
                    let classifier_arc = config.full_mail_classifier.as_ref().unwrap().clone();

                    let truncate = args.truncate;
                    thread::spawn(move || {
                        let reader = BufReader::new(&stream);
                        let writer = BufWriter::new(&stream);

                        // Create thread-local Config with Owned classifier
                        let thread_config = Config {
                            full_mail_classifier: Some(classifier_arc),
                            fork_mode_enabled: false,
                        };

                        if let Err(e) = process_client(&thread_config, reader, writer, truncate) {
                            eprintln!("thread error: {e}");
                        }

                        // Decrement count and signal
                        let (lock, cvar) = &*state_clone;
                        let mut count = lock.lock().unwrap();
                        *count -= 1;
                        cvar.notify_one();
                    });
                } else {
                    let stream: TcpStream = socket.into();
                    let reader = BufReader::new(&stream);
                    let writer = BufWriter::new(&stream);
                    if let Err(e) = process_client(config, reader, writer, args.truncate) {
                        eprintln!("{e}");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(e) => eprintln!("fork: {e}"),
        }
        if FLAG_SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
    }

    // Wait for active threads to complete
    if let Some(ref state) = thread_state {
        let (lock, cvar) = state.as_ref();
        let mut count = lock.lock().unwrap();
        while *count > 0 {
            eprintln!("Waiting for {} threads to complete", *count);
            let result = cvar.wait_timeout(count, Duration::from_secs(1)).unwrap();
            count = result.0;
        }
    }

    Ok(())
}

fn simulate_client(config: &Config) -> Result<(), Box<dyn Error>> {
    let storage = MailInfoStorage {
        id: "test".into(),
        recipients: ["testrecipient".into()].into(),
        sender: "testsender".into(),
        mail_buffer: b"From: me\nTo: yu\nSubject: test\n\nTest".to_vec(),
        ..Default::default()
    };
    let _result = classify_mail(config, &storage);
    Ok(())
}

#[rustfmt::skip]
#[allow(unused_variables, dead_code)]
pub fn simulate(config: &Config, args: &DaemonArgs) -> Result<(), Box<dyn Error>> {
//    #[cfg(feature = "systemd")]
//    let listen_socket = match systemd::daemon::listen_fds(false).unwrap().iter().next() {
//        Some(fd) => unsafe { Socket::from_raw_fd(fd) },
//        None => {
//            let address: SocketAddr = args.address.parse()?;
//            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
//            socket.set_reuse_address(true)?;
//            socket.bind(&address.into())?;
//            socket.listen(1)?;
//            socket
//        }
//    };
//
//    #[cfg(not(feature = "systemd"))]
//    let listen_socket = {
//        let address: SocketAddr = args.address.parse()?;
//        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
//        socket.set_reuse_address(true)?;
//        socket.bind(&address.into())?;
//        socket.listen(1)?;
//        socket
//    };
//
    if args.fork_max > 0 && args.threads_max > 0 {
        return Err("Cannot use both fork and thread modes simultaneously".into());
    }

    let thread_state: Option<Arc<(Mutex<u16>, Condvar)>> = if args.threads_max > 0 {
        Some(Arc::new((Mutex::new(0), Condvar::new())))
    } else {
        None
    };

    install_signal_handler();
    let mut simulate_cnt = 8;
    loop {
        if simulate_cnt == 0 {
            break;
        } else {
            simulate_cnt -= 1
        }
        if args.fork_max > 0 {
            while CHILDREN_CNT.load(Ordering::Relaxed) >= args.fork_max {
                pause()
            }
        } else if let Some(ref state) = thread_state {
            let (lock, cvar) = state.as_ref();
            let mut count = lock.lock().unwrap();
            while *count >= args.threads_max {
                count = cvar.wait(count).unwrap();
            }
        }
//        match listen_socket.accept() {
//            Ok((socket, _addr)) => {
                if args.fork_max > 0 {
                    match unsafe { fork() } {
                        Ok(ForkResult::Parent { .. }) => {
                            CHILDREN_CNT.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(ForkResult::Child) => {
//                            drop(listen_socket);
//                            let stream: TcpStream = socket.into();
//                            let reader = BufReader::new(&stream);
//                            let writer = BufWriter::new(&stream);
//                            match process_client(config, reader, writer, args.truncate) {
                            match simulate_client(config) {
                                Ok(_) => exit(0),
                                Err(e) => {
                                    eprintln!("{e}");
                                    exit(1)
                                }
                            }
                        }
                        Err(e) => eprintln!("fork: {e}"),
                    }
                } else if args.threads_max > 0 {
                    let state_clone = thread_state.as_ref().unwrap().clone();

                    // Increment thread count
                    {
                        let (lock, _) = state_clone.as_ref();
                        let mut count = lock.lock().unwrap();
                        *count += 1;
                    }

//                    let stream: TcpStream = socket.into();

                    // Extract Arc from config
                    let classifier_arc = config.full_mail_classifier.as_ref().unwrap().clone();

                    let truncate = args.truncate;
                    thread::spawn(move || {
//                        let reader = BufReader::new(&stream);
//                        let writer = BufWriter::new(&stream);

                        // Create thread-local Config with Owned classifier
                        let thread_config = Config {
                            full_mail_classifier: Some(classifier_arc),
                            fork_mode_enabled: false,
                        };

//                        if let Err(e) = process_client(&thread_config, reader, writer, truncate) {
                        if let Err(e) = simulate_client(&thread_config) {
                            eprintln!("thread error: {e}");
                        }

                        // Decrement count and signal
                        let (lock, cvar) = &*state_clone;
                        let mut count = lock.lock().unwrap();
                        *count -= 1;
                        cvar.notify_one();
                    });
                } else {
//                    let stream: TcpStream = socket.into();
//                    let reader = BufReader::new(&stream);
//                    let writer = BufWriter::new(&stream);
//                    if let Err(e) = process_client(config, reader, writer, args.truncate) {
                    if let Err(e) = simulate_client(config) {
                        eprintln!("{e}");
                    }
                }
//            }
//            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
//            Err(e) => eprintln!("fork: {e}"),
//        }
        if FLAG_SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
    }

    // Wait for active threads to complete
    if let Some(ref state) = thread_state {
        let (lock, cvar) = state.as_ref();
        let mut count = lock.lock().unwrap();
        while *count > 0 {
            eprintln!("Waiting for {} threads to complete", *count);
            let result = cvar.wait_timeout(count, Duration::from_secs(1)).unwrap();
            count = result.0;
        }
    }
    Ok(())
}
