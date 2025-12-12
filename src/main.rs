#![allow(unused_macros)]
mod classify;

fn main() -> impl std::process::Termination {
    srmilter::cli::xmain(classify::classify)
}
