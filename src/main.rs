use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::io::{self, Write};
// use std::env;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Name of the network interface to use.
    #[arg(short, long, conflicts_with = "list", default_value = "eth0")]
    interface: String,
    
    // Select the network interface to use.
    #[arg(short, long, conflicts_with = "interface")]
    select: bool,
    
    // List network interfaces.
    #[arg(short, long, conflicts_with = "interface")]
    list: bool,
}

fn main() {
    let interfaces = datalink::interfaces();
    let interface_name;
    let args = Args::parse();
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
        io::stdin().read_line(&mut input).expect("Failed to read line");
        let choice: usize = input.trim().parse().expect("Invalid input");
        
        let selected_interface = interfaces.get(choice).expect("Selected interface does not exist");
        interface_name = selected_interface.name.clone();
    } else if args.interface.is_empty() {
        interface_name = "eth0".to_string();
    } else {
        interface_name = args.interface;
    }
    let interface = interfaces.into_iter()
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
            },
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            },
        }
    }
}

fn handle_packet(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                println!("IPv4 packet: {} > {} proto {:?} len {}", header.get_source(), header.get_destination(), protocol_to_str(header.get_next_level_protocol()), header.get_total_length());
                let payload = header.payload();
                println!("{}", to_hex_string(payload));
            }
        },
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                println!("IPv6 packet: {} > {} next header {:?} payload len {}", header.get_source(), header.get_destination(), protocol_to_str(header.get_next_header()), header.get_payload_length());
                let payload = header.payload();
                println!("{}", to_hex_string(payload));
            }
        },
        _ => println!("Other packet: {}", ethernet.packet().len()),
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" ")
}

fn protocol_to_str(proto: IpNextHeaderProtocol) -> &'static str {
    match proto {
        IpNextHeaderProtocol(17) => "UDP",
        IpNextHeaderProtocol(6) => "TCP",
        IpNextHeaderProtocol(1) => "ICMP",
        IpNextHeaderProtocol(2) => "IGMP",
        IpNextHeaderProtocol(89) => "OSPF",
        IpNextHeaderProtocol(50) => "ESP",
        _ => "Other",
    }
}
