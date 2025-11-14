
# 🛰️ LogSentinel Parser


**LogSentinel** is a high-performance log parsing library written in **Rust**, designed to handle logs from multiple sources with reliability and speed. Maintained by **Ethosevo**, LogSentinel provides developers and DevOps engineers with a flexible, extensible, and production-ready log parser. It currently supports Nginx logs, Syslog logs, and Docker logs (coming soon). With advanced parsing capabilities, cross-platform support, and high performance, LogSentinel is ideal for production environments.

---

## 📦 Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
logsentinel-parser = { git = "https://github.com/Radeonares32/LogSentinel-Parser.git" }

[dependencies]
logsentinel-parser = "0.1.0" # Use the latest version
```

📝 Usage

```rust
use logsentinel_parser::nginx::parse_nginx_log;

fn main() {
    let log_line = r#"127.0.0.1 - - [14/Nov/2025:20:01:23 +0300] "GET /index.html HTTP/1.1" 200 1024"#;
    let parsed = parse_nginx_log(log_line).unwrap();

    println!("{:#?}", parsed);
    // Example Output:
    // {
    //    ip: "127.0.0.1",
    //    timestamp: "2025-11-14T20:01:23+03:00",
    //    method: "GET",
    //    path: "/index.html",
    //    status: 200,
    //    size: 1024
    // }
}
```

```rust
use logsentinel_parser::syslog::parse_syslog;
fn main() {
    let log_line = r#"<34>1 2025-11-14T20:01:23+03:00 myhost appname 1234 ID47 [exampleSDID@32473 iut="3" eventSource="syslog"] This is a test log message"#;
    let parsed = parse_syslog(log_line).unwrap();

    println!("{:#?}", parsed);
    // Example Output:
    // {
    //    facility: 4,
    //    severity: 2,
    //    timestamp: "2025-11-14T20:01:23+03:00",
    //    hostname: "myhost",
    //    appname: "appname",
    //    pid: 1234,
    //    message: "This is a test log message",
    //    structured_data: { iut: "3", eventSource: "syslog" }
    // }
}
```

🗺️ Roadmap
We are actively developing LogSentinel. Planned features include:

Docker Parser: Full support including container ID, image, labels, exit code, restart count, and health status extraction.

Apache Log Support: Support for Apache access and error log formats.

JSON Log Support: Optimized parser for structured JSON logs.

Grok-like DSL: A Domain Specific Language (DSL) to allow users to easily define their own parser rules.

🛠️ Contributing
Contributions are welcome! They help make the project better.

Feature Requests: Open an issue to request new parsers or custom log type support.

Bug Reports: Please provide sample log lines to help us reproduce parsing issues.

Pull Requests: Fork the repository, create a branch for your feature, and open a Pull Request (PR).


📄 License
This project is licensed under the MIT License.
