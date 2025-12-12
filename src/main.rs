#![allow(unused_macros)]

use srmilter::cli::xmain;
use std::process::ExitCode;

mod classify;

fn main() -> ExitCode {
    match xmain(classify::classify) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
