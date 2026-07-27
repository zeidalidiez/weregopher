//! Repository-only JSONL process fixture for app-server session tests.

use std::{
    env,
    io::{self, BufRead as _, Write as _},
    process::{self, Command, Stdio},
    thread,
    time::Duration,
};

const INITIALIZE_RESPONSE: &str = r#" { "id":"init-secret", "result":{"serverInfo":{"name":"fixture"},"future":{"kept":true}}, "unknownTopLevel":9 } "#;
const READY_NOTIFICATION: &str =
    r#"{ "method":"fixture/ready", "params":{"unknown":true}, "futureField":7 }"#;
const SERVER_REQUEST: &str = r#"{"id":"server-secret","method":"approval/request","params":{"reason":"fixture","unknown":true}}"#;
const CLIENT_RESPONSE: &str =
    r#"{ "id":7, "result":{"newVariant":{"preserved":true}}, "unknownResponse":11 }"#;
const INITIALIZE_ERROR: &str =
    r#"{"id":"init-secret","error":{"code":-32000,"message":"fixture rejection"}}"#;

fn write_line(stdout: &mut io::StdoutLock<'_>, line: &str) -> io::Result<()> {
    stdout.write_all(line.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn run_session(mode: &str) -> io::Result<()> {
    if mode == "hold-stdio" {
        thread::sleep(Duration::from_secs(2));
        return Ok(());
    }
    if mode == "silent" {
        thread::sleep(Duration::from_mins(1));
        return Ok(());
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut lines = stdin.lock().lines();
    let mut output = stdout.lock();

    if mode == "oversized" {
        output.write_all(&vec![b'x'; 2_048])?;
        output.write_all(b"\n")?;
        output.flush()?;
        thread::sleep(Duration::from_mins(1));
        return Ok(());
    }

    let Some(initialize) = lines.next().transpose()? else {
        return Ok(());
    };
    if !initialize.contains(r#""method":"initialize""#)
        && !initialize.contains(r#""method": "initialize""#)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture expected initialize",
        ));
    }
    if mode == "reject" {
        write_line(&mut output, INITIALIZE_ERROR)?;
        thread::sleep(Duration::from_mins(1));
        return Ok(());
    }
    write_line(&mut output, INITIALIZE_RESPONSE)?;

    let Some(initialized) = lines.next().transpose()? else {
        return Ok(());
    };
    if !initialized.contains(r#""method":"initialized""#)
        && !initialized.contains(r#""method": "initialized""#)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture expected initialized",
        ));
    }

    if mode == "crash" {
        process::exit(42);
    }
    if mode == "exit" {
        return Ok(());
    }
    if mode == "linger-stdio" {
        let executable = env::current_exe()?;
        drop(
            Command::new(executable)
                .arg("hold-stdio")
                .stdin(Stdio::null())
                .spawn()?,
        );
        return Ok(());
    }
    if mode == "no-response" {
        for line in lines {
            drop(line?);
        }
        return Ok(());
    }
    if mode == "hang" {
        thread::sleep(Duration::from_mins(1));
        return Ok(());
    }

    writeln!(io::stderr(), "fixture-secret-stderr")?;
    write_line(&mut output, READY_NOTIFICATION)?;
    write_line(&mut output, SERVER_REQUEST)?;

    for line in lines {
        let line = line?;
        if line.contains(r#""method":"future/do""#) || line.contains(r#""method": "future/do""#) {
            write_line(&mut output, CLIENT_RESPONSE)?;
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mode = env::args().nth(1).unwrap_or_else(|| "normal".to_owned());
    run_session(&mode)
}
