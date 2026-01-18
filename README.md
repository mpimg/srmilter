# srmilter

A Rust library for building mail filter (milter) daemons that integrate with Postfix.

## Overview

srmilter implements the milter protocol to receive emails from Postfix, parse them, and return classification decisions (accept, reject, or quarantine). It provides a simple API for writing custom email classifiers.

## Features

- Full milter protocol implementation for Postfix integration
- Email parsing via `mail-parser` crate
- Multiple concurrency modes: single-threaded, forked processes, or threaded
- Spamhaus ZEN DNSBL lookup utilities
- systemd socket activation support (optional)
- Built-in CLI with test and dump commands

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
srmilter = "3.0"
```

### Example

```rust
use srmilter::{ClassifyResult, Config, EmailClassifier, MailInfo, read_array, array_contains};

struct MyContext {
    blocklist: Vec<String>,
}

fn main() -> impl std::process::Termination {
    let ctx = MyContext {
        blocklist: read_array("/etc/srmilter/blocklist.txt").unwrap_or_default(),
    };
    let classifier = EmailClassifier::builder(ctx).classify_fn(classify).build();
    let config = Config::builder()
        .email_classifier(classifier)
        .enable_fork_mode()
        .build();
    srmilter::cli::cli(&config)
}

fn classify(ctx: &MyContext, mail_info: &MailInfo) -> ClassifyResult {
    if array_contains(&ctx.blocklist, mail_info.get_from_address()) {
        return mail_info.reject("sender on blocklist");
    }
    mail_info.accept("default")
}
```

## CLI Commands

The built-in CLI provides three subcommands:

```bash
# Run the milter daemon (default: 0.0.0.0:7044)
myfilter daemon [address] [--fork N] [--threads N] [--truncate N]

# Test classifier against an .eml file
myfilter test <file.eml> [sender] [recipients...]

# Dump parsed email headers and body
myfilter dump <file.eml> [-H] [-b] [--html]
```

### Concurrency Options

- **Default**: Single-threaded, sequential processing
- `--fork N`: Fork up to N child processes (requires `enable_fork_mode()`)
- `--threads N`: Use up to N threads

## Postfix Configuration

Add to your Postfix `main.cf`:

```
smtpd_milters = inet:127.0.0.1:7044
```

## License

Copyright © 2025 Donald Buczek <buczek@molgen.mpg.de>

Licensed under the European Union Public Licence (EUPL), Version 1.2.
See the [LICENSE](LICENSE) file for details.
