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
    #[arg(long, default_value_t = 1)]
    timeout: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let gateway = Ipv4Addr::from_str(&args.gateway)?;
    let target_ip = Ipv4Addr::from_str(&args.target_ip)?;
    let interface = toycpip::get_network_interface(&args.interface_name)?;

    toycpip::setup(interface, gateway)?;

    let mac_addr = toycpip::arp_request(target_ip, Some(args.timeout))?;
    println!("mac address for ip({}) is {}", target_ip, mac_addr);

    Ok(())
}
