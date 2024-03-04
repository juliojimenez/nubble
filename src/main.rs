use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use std::env;

fn main() {
    let interfaces = datalink::interfaces();
    let interface_name = env::args().nth(1).unwrap();
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Failed to get interface.");
}
