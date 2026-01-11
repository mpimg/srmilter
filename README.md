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
srmilter = "2.0"
```

### Basic Example

```rust
use srmilter::{ClassifyResult, Config, FullEmailFnClassifier, MailInfo};

fn main() -> impl std::process::Termination {
    let classifier = FullEmailFnClassifier::new(classify);
    let config = Config::builder()
        .full_mail_classifier(&classifier)
        .build();
    srmilter::cli::cli(&config)
}

fn classify(mail_info: &MailInfo) -> ClassifyResult {
    let from = mail_info.get_from_address();
    let subject = mail_info.get_subject();

    if from.ends_with("@spam.example.com") {
        return mail_info.reject("blocked sender domain");
    }

    if subject.contains("FREE MONEY") {
        return mail_info.quarantine("suspicious subject");
    }

    mail_info.accept("default")
}
```

### Thread-Safe Classifier

For `--threads` mode, use `Arc`-wrapped classifiers:

```rust
use std::sync::Arc;
use srmilter::{ClassifyResult, Config, FullEmailFnClassifier, MailInfo};

fn main() -> impl std::process::Termination {
    let classifier = Arc::new(FullEmailFnClassifier::new(classify));
    let config = Config::builder()
        .full_mail_classifier_arc(classifier)
        .build();
    srmilter::cli::cli(&config)
}

fn classify(mail_info: &MailInfo) -> ClassifyResult {
    mail_info.accept("default")
}
```

### Classifier with Context

For classifiers that need configuration loaded at startup:

```rust
use srmilter::{ClassifyResult, Config, FullEmailFnClassifierWithCtx, MailInfo, read_array, array_contains};

struct MyContext {
    blocklist: Vec<String>,
}

fn main() -> impl std::process::Termination {
    let ctx = MyContext {
        blocklist: read_array("/etc/srmilter/blocklist.txt").unwrap_or_default(),
    };
    let classifier = FullEmailFnClassifierWithCtx::new(&ctx, classify);
    let config = Config::builder()
        .full_mail_classifier(&classifier)
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
- `--threads N`: Use up to N threads (requires `Arc`-based classifier)

## Postfix Configuration

Add to your Postfix `main.cf`:

```
smtpd_milters = inet:127.0.0.1:7044
```

## Building

```bash
# With systemd support (default)
cargo build --release

# Without systemd support
cargo build --release --no-default-features
```

## Examples

See the `examples/` directory for complete working examples:

- `example_1.rs` - Simple function classifier
- `example_2.rs` - Thread-safe classifier for `--threads` mode
- `example_3.rs` - Classifier with borrowed context
- `example_4.rs` - Thread-safe classifier with `Arc` context
