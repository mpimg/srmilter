# srmilter

A Rust library for building mail filter (milter) daemons that integrate with Postfix.

## Overview

srmilter implements the milter protocol to receive emails from Postfix, parse them, and return classification decisions (accept, reject, or quarantine). It provides a simple API for writing custom email classifiers.

## Features

- Milter protocol implementation for Postfix integration
- Email parsing via `mail-parser` crate
- Multithreading
- Spamhaus ZEN DNSBL lookup utilities
- systemd socket activation support (optional)
- Built-in CLI

## Usage

1. Create a new binary crate:
   ```bash
   cargo init myfilter
   cd myfilter
   ```

2. Add srmilter as a dependency:
   ```bash
   cargo add srmilter
   ```

3. Edit `src/main.rs` to create your milter binary (see example below).

### Example

```rust
use srmilter::{ClassifyResult, Config, EmailClassifier, MailInfo};

struct Ctx {
    // whatever
}

fn main() -> impl std::process::Termination {
    let ctx = Ctx {};
    let classifier =
EmailClassifier::builder(ctx).classify_fn(classify).build();
    let config = Config::builder().email_classifier(classifier).build();
    srmilter::cli::cli(&config)
}

fn classify(_ctx: &Ctx, mail_info: &MailInfo) -> ClassifyResult {
    let from_address = mail_info.get_from_address();

    if from_address == "spammer@example.com" {
        return mail_info.reject("banned from_address");
    }
    mail_info.accept("default")
}

```

## CLI Commands

The built-in CLI provides two subcommands:

```bash
# Run the milter daemon (default: 0.0.0.0:7044)
myfilter daemon [address] [--threads N] [--truncate N]

# Test classifier against an .eml file
myfilter test <file.eml> [sender] [recipients...]
```

### Concurrency Options

- **Default**: Up to 64 threads
- `--threads N`: Use up to N threads

## systemd Deployment with Zero-Downtime Reloads

`reload-proxy` is a supervisor binary that enables zero-downtime reloads of a
srmilter-based daemon under systemd socket activation.

### How it works

1. systemd creates the listen socket and passes it to `reload-proxy` as FD 3
   (via `LISTEN_FDS`).
2. `reload-proxy` forwards the socket to the milter daemon via the
   `SRMILTER_LISTEN_FD=3` environment variable and spawns it as a child.
3. On `systemctl reload`, systemd sends `SIGHUP` to `reload-proxy`, which
   spawns a new child instance (sharing the same listen socket), then sends
   `SIGINT` to the old instance.
4. Both instances overlap briefly; the old one finishes its in-flight
   connections before exiting. No connections are dropped.

### Unit files

`mymilter.socket`:
```ini
[Socket]
ListenStream=127.0.0.1:7044

[Install]
WantedBy=sockets.target
```

`mymilter.service`:
```ini
[Unit]
Requires=mymilter.socket
After=mymilter.socket

[Service]
Type=exec
ExecStart=/usr/local/bin/reload-proxy /usr/local/bin/mymilter daemon --threads 64
ExecReload=/bin/kill -HUP $MAINPID
TimeoutStopSec=15s
SyslogFacility=mail
SyslogIdentifier=mymilter
```

`TimeoutStopSec` should be set to the maximum time you are willing to wait
for in-flight connections to complete. On `systemctl stop`, systemd sends `SIGTERM`
to `reload-proxy`, which will then also terminate its children.

### Triggering a reload

```bash
systemctl reload mymilter
```

## Postfix Configuration

Add to your Postfix `main.cf`:

```
smtpd_milters = inet:127.0.0.1:7044
```

## License

Copyright © 2025 Donald Buczek <buczek@molgen.mpg.de>

Licensed under the European Union Public Licence (EUPL), Version 1.2.
See the [LICENSE](LICENSE) file for details.
