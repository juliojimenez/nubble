use clap::CommandFactory;
use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::ArpOperation;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::env;
use std::io::{self, Write};
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the network interface to use.
    #[arg(short, long, default_value = "")]
    interface: String,

    /// Select the network interface to use.
    #[arg(short, long)]
    select: bool,

    /// List network interfaces.
    #[arg(short, long)]
    list: bool,

    /// Create a symlink in /usr/local/bin.
    #[arg(long)]
    symlink: bool,
}

fn main() {
    let interfaces = datalink::interfaces();
    let interface_name;
    let args = Args::parse();
    let mut cmd = Args::command();
    if args.list {
        println!("Available interfaces:");
        for (index, iface) in interfaces.iter().enumerate() {
            println!("{}: {}", index, iface.name);
        }
        return;
    }
    if args.select {
        println!("Available interfaces:");
        for (index, iface) in interfaces.iter().enumerate() {
            println!("{}: {}", index, iface.name);
        }
        print!("Select an interface by index: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        let choice: usize = input.trim().parse().expect("Invalid input");

        let selected_interface = interfaces
            .get(choice)
            .expect("Selected interface does not exist");
        interface_name = selected_interface.name.clone();
    } else if !args.interface.is_empty() {
        interface_name = args.interface;
    } else if args.symlink {
        let current_exe = match env::current_exe() {
            Ok(exe) => exe,
            Err(e) => panic!("Failed to get current executable path: {}", e),
        };
        let symlink_path = Path::new("/usr/local/bin/nubble");
        match unix_fs::symlink(current_exe, symlink_path) {
            Ok(_) => println!("Created symlink at {}", symlink_path.display()),
            Err(e) => panic!("Failed to create symlink: {}", e),
        };
        return;
    } else {
        cmd.print_help().unwrap();
        return;
    }
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to get interface.");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                handle_packet(&packet);
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn handle_packet(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                println!(
                    "{} IP {} > {} proto {} len {}",
                    timestamp(),
                    header.get_source(),
                    header.get_destination(),
                    protocol_to_str(header.get_next_level_protocol()),
                    header.get_total_length()
                );
                let payload = header.payload();
                println!("{}", to_hex_string(payload));
                println!("{}", payload_to_ascii(payload));
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                println!(
                    "IPv6 packet: {} > {} next header {} payload len {}",
                    header.get_source(),
                    header.get_destination(),
                    protocol_to_str(header.get_next_header()),
                    header.get_payload_length()
                );
                let payload = header.payload();
                println!("{}", to_hex_string(payload));
                println!("{}", payload_to_ascii(payload));
            }
        }
        EtherTypes::Arp => {
            if let Some(header) = ArpPacket::new(ethernet.payload()) {
                println!(
                    "ARP packet: {} > {} operation {} len {}",
                    header.get_sender_proto_addr(),
                    header.get_target_proto_addr(),
                    arp_operation_to_str(header.get_operation()),
                    header.packet().len()
                );
                let payload = header.payload();
                println!("{}", to_hex_string(payload));
                println!("{}", payload_to_ascii(payload));
            }
        }
        _ => println!("Other packet: {}", ethernet.packet().len()),
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

fn payload_to_ascii(payload: &[u8]) -> String {
    payload
        .iter()
        .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
        .collect()
}

fn protocol_to_str(proto: IpNextHeaderProtocol) -> &'static str {
    match proto {
        IpNextHeaderProtocol(17) => "UDP",
        IpNextHeaderProtocol(6) => "TCP",
        IpNextHeaderProtocol(1) => "ICMP",
        IpNextHeaderProtocol(2) => "IGMP",
        IpNextHeaderProtocol(89) => "OSPF",
        IpNextHeaderProtocol(50) => "ESP",
        _ => "Other".trim_matches('"'),
    }
}

fn arp_operation_to_str(op: ArpOperation) -> &'static str {
    match op {
        ArpOperation(1) => "Request",
        ArpOperation(2) => "Reply",
        _ => "Other".trim_matches('"'),
    }
}

fn timestamp() -> String {
    if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let total_seconds = duration_since_epoch.as_secs();
        let hours = total_seconds / 3600 % 24; // Assuming UTC+0 timezone
        let minutes = total_seconds % 3600 / 60;
        let seconds = total_seconds % 60;
        let microseconds = duration_since_epoch.subsec_micros();

        return format!(
            "{:02}:{:02}:{:02}.{:06}",
            hours, minutes, seconds, microseconds
        );
    } else {
        return "00:00:00.000000".to_string();
    }
}
