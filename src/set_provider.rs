use std::process::{Child, Command, Stdio};
use std::os::unix::io::{AsRawFd, FromRawFd};

fn stdout_to_stdin(process: &Child) -> Option<Stdio> {
    if let Some(ref stdout) = process.stdout {
        return Some(unsafe { Stdio::from_raw_fd(stdout.as_raw_fd()) });
    }
    None
}

fn main() {
    // Bootstrap
    Command::new("cargo")
        .arg("run")
        .arg("--")
        .arg("--listen-address")
        .arg("/ip4/127.0.0.1/tcp/40837")
        .arg("--secret-key-seed")
        .arg("1")
        .arg("provide")
        //.stdout(Stdio::piped())
        .spawn().expect("failed to start");


    let port = 40838;
    for i in 2..3 {
        Command::new("cargo")
            .arg("run")
            .arg("--")
            .arg("--peer")
            .arg("/ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X")
            .arg("--listen-address")
            .arg(format!("/ip4/127.0.0.1/tcp/{}", port + i))
            .arg("--secret-key-seed")
            .arg(i.to_string())
            .arg("provide")
            //.stdout(Stdio::piped())
            .spawn().expect("failed to start");
    }

}