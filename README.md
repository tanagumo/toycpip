# toycpip

A toy TCP/IP stack implementation in Rust for learning network protocols.

## Overview

`toycpip` is an educational TCP/IP stack implementation written in Rust. The project aims to provide hands-on experience with network protocol implementation, focusing on type safety, clean architecture, and RFC compliance.

## Features

### Implemented Layers

- **Ethernet Layer**: Frame parsing, generation, and transmission
- **ARP Layer**: Address Resolution Protocol implementation
- **IP Layer**: IPv4 packet handling with checksum validation
- **ICMP Layer**: Internet Control Message Protocol with ping functionality

### Key Design Principles

- **Type Safety**: Custom types for protocol fields (Version, IHL, Flag, etc.)
- **Error Handling**: Comprehensive error types with proper propagation
- **Observer Pattern**: Layer-to-layer communication via message passing
- **RFC Compliance**: Protocol implementation following internet standards
- **Memory Efficiency**: Optimized packet serialization and parsing

## Requirements

- Rust (edition 2024)
- Administrator/root privileges (for raw socket access)
- Network interface access

## Dependencies

- `pnet`: Network interface handling
- `thiserror`: Error handling
- `log`: Logging framework
- `clap`: Command-line argument parsing
- `env_logger`: Environment-based logging
- `fastrand`: Random number generation

## Installation

```bash
git clone <repository-url>
cd toycpip
cargo build --release
```

## Usage

### Ping Command

Send ICMP echo requests to a target host:

```bash
# Single ping
sudo cargo run --bin ping -- --target-ip 8.8.8.8 --interface-name eth0 --gateway 192.168.1.1

# Multiple pings
sudo cargo run --bin ping -- -c 3 --target-ip 8.8.8.8 --interface-name eth0 --gateway 192.168.1.1
```

Example output:
```
PING 8.8.8.8
28 bytes from 8.8.8.8: icmp_seq=1 time=12.34 ms
28 bytes from 8.8.8.8: icmp_seq=2 time=11.89 ms
28 bytes from 8.8.8.8: icmp_seq=3 time=13.21 ms
```

### ARP Command

Perform ARP resolution for a target IP:

```bash
sudo cargo run --bin arp -- --target-ip 192.168.100.1 --interface-name eth0 --gateway 192.168.100.1
```

Example output:
```
mac address for ip(192.168.100.1) is 08:33:ed:50:0c:d2
```

### Library Usage

```rust
use toycpip;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup network interface
    let interface = toycpip::get_network_interface("eth0")?;
    toycpip::setup(interface, Ipv4Addr::new(192, 168, 1, 1))?;
    
    // Send ICMP request
    let target_ip: Ipv4Addr = "8.8.8.8".parse()?;
    let result = toycpip::send_icmp_request(target_ip, 1)?;
    println!("Response time: {:.2} ms", result.elapsed().as_secs_f64() * 1000.0);
    
    Ok(())
}
```

## Architecture

### Layer Organization

```
┌─────────────┐
│ Application │ (ping, arp commands)
├─────────────┤
│    ICMP     │ (icmp.rs)
├─────────────┤
│     IP      │ (ip.rs)
├─────────────┤
│     ARP     │ (arp.rs)
├─────────────┤
│  Ethernet   │ (ethernet.rs)
├─────────────┤
│  Physical   │ (via pnet)
└─────────────┘
```

### Key Components

- **Protocol Stacks**: Each layer implements packet parsing, generation, and transmission
- **Type Safety**: Custom wrapper types prevent common protocol implementation errors
- **Observer Pattern**: Asynchronous communication between layers using channels
- **Host Configuration**: Centralized network configuration management (host.rs)
- **Utilities**: Checksum calculation and common helper functions (utils.rs)

## Development Status

### ✅ Completed
- Ethernet frame handling
- ARP resolution and caching
- IPv4 packet processing
- ICMP echo request/reply
- Working ping and arp utilities

### 🚧 Planned
- TCP implementation
- Connection establishment (3-way handshake)
- Reliable data transmission
- Flow control and congestion control

## Limitations and Design Decisions

Since this is an educational project focused on understanding core networking concepts, several simplifications have been made:

### Non-functional Requirements
- **No caching mechanisms**: ARP entries are not cached for performance
- **No connection pooling**: Each request creates new connections
- **Limited error recovery**: Basic error handling without sophisticated retry logic
- **No performance optimization**: Focus on readability over speed
- **No async I/O**: Uses standard multithreading instead of async runtime (tokio, etc.)

### Protocol Compliance
- **Not strictly RFC-compliant**: Core functionality implemented, edge cases omitted
- **IP fragmentation not supported**: Assumes MTU-sized packets only
- **Limited protocol variants**: IPv4 only, no IPv6 support
- **Simplified state machines**: Basic implementations without full protocol state tracking

### Educational Focus
- **Learning over production**: Code prioritizes understanding over robustness
- **Core concepts**: Implements essential protocol features for educational value
- **Type safety demonstration**: Shows how Rust's type system prevents common networking bugs
- **AI-assisted development**: Implementation developed through discussions and code reviews with AI assistance

## Learning Outcomes

This project provides hands-on experience with:

- Low-level network programming
- Protocol implementation details
- Rust's type system for system programming
- Asynchronous programming with channels
- Raw socket programming
- Network packet analysis

## Contributing

This is primarily an educational project. Feel free to explore the code, suggest improvements, or use it as a reference for your own learning.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- RFC specifications for protocol standards
- The pnet crate for low-level network access
- Rust community for excellent tooling and documentation