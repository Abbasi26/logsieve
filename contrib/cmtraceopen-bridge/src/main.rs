//! logsieve-cmtraceopen: read one log file, parse it with cmtraceopen-parser, print JSON on stdout.
//!
//! The bridge is read-only. It opens the file named on the command line, does not write
//! anything, and makes no network calls. logsieve calls it once per file when
//! `--parser cmtraceopen` is selected.

use std::process::ExitCode;

use cmtraceopen_parser::parser::{decode_bytes, detect_encoding, parse_content};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "--version" || args[1] == "-V") {
        println!("logsieve-cmtraceopen {} (cmtraceopen-parser 0.1.1)", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.len() != 2 {
        eprintln!("usage: logsieve-cmtraceopen <log file>");
        return ExitCode::from(2);
    }
    let path = &args[1];
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("logsieve-cmtraceopen: cannot read {path}: {err}");
            return ExitCode::from(1);
        }
    };
    let encoding = detect_encoding(&bytes);
    let content = match decode_bytes(&bytes, encoding) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("logsieve-cmtraceopen: cannot decode {path}: {err}");
            return ExitCode::from(1);
        }
    };
    let (result, _parser) = parse_content(&content, path, bytes.len() as u64);
    match serde_json::to_string(&result) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("logsieve-cmtraceopen: cannot serialize result: {err}");
            ExitCode::from(1)
        }
    }
}
