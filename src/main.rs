use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{self, EtherTypes, EthernetPacket};
use pnet::packet::{self, Packet};
use std::env;

fn main() {
    let interfaces = datalink::interfaces();
    let interface_name = env::args().nth(1).unwrap();
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
        EtherTypes::Ipv4 => println!("IPv4 packet: {}", ethernet.packet().len()),
        EtherTypes::Ipv6 => println!("IPv6 packet: {}", ethernet.packet().len()),
        _ => println!("Other packet: {}", ethernet.packet().len()),
    }
}
