use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn workload_binary_serves_health_and_reports_bind_failure() {
    let binary = env!("CARGO_BIN_EXE_tinylayer-workload");
    let mut child = ChildGuard(
        Command::new(binary)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match TcpStream::connect("127.0.0.1:8080") {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "workload exited early: {error}"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("workload did not listen: {error}"),
        }
    };
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("ok"));

    child.0.kill().unwrap();
    child.0.wait().unwrap();

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
    let failed = Command::new(binary).output().unwrap();
    drop(listener);
    assert!(!failed.status.success());
    assert!(!failed.stderr.is_empty());
}
