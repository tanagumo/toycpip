use std::thread;
use std::time::Duration;
use std::{net::Ipv4Addr, str::FromStr};

use clap::Parser;
use env_logger;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    target_ip: String,
    #[arg(long)]
    interface_name: String,
    #[arg(long)]
    gateway: String,
    #[arg(short, default_value = "1")]
    count: u16,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let gateway = Ipv4Addr::from_str(&args.gateway)?;
    let target_ip = Ipv4Addr::from_str(&args.target_ip)?;
    let interface = toycpip::get_network_interface(&args.interface_name)?;

    toycpip::setup(interface, gateway)?;

    println!("PING {}", &args.target_ip);
    for i in 1..=args.count {
        match toycpip::send_icmp_request(target_ip, i) {
            Ok(info) => {
                println!(
                    "{} bytes from {}: icmp_seq={} time={:.2} ms",
                    info.bytes_sent(),
                    args.target_ip,
                    info.sequence(),
                    info.elapsed().as_secs_f64() * 1000.0,
                );
            }
            Err(e) => {
                println!("failed to send ping to {}: {}", args.target_ip, e);
            }
        }
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}
