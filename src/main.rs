use std::env::args;
use std::mem::{self, transmute};
use std::os::fd::AsRawFd;
use std::ptr;
use std::{error::Error, io::ErrorKind, mem::MaybeUninit, sync::Arc, time::Duration};

use csv::StringRecord;
use pnet::packet::{
    icmp::{
        echo_reply::EchoReplyPacket, echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket,
        IcmpTypes,
    },
    ipv4::Ipv4Packet,
    Packet,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::Ipv4Addr;
use tokio::task::JoinSet;

#[derive(serde::Deserialize)]
struct InputAddr {
    address: Ipv4Addr,
    count: usize,
    interval: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let target = get_first_arg()?;
    let record = StringRecord::from(target.split(',').collect::<Vec<_>>());
    let input: InputAddr = record.deserialize(None)?;

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    let socket = Arc::new(socket);

    // create the "sockaddr"
    let mut addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&addr_storage) as libc::socklen_t;

    let res = unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut addr_storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };

    if res == -1 {
        panic!("Could not get socket address and size");
    }

    let address = unsafe { SockAddr::new(addr_storage, len) };

    let mut address = address.as_socket_ipv4().unwrap();
    address.set_ip(input.address);
    let address: SockAddr = address.into();
    let address = Arc::new(address);
    let mut set = JoinSet::new();

    for i in 0..input.count {
        let inner_socket = Arc::clone(&socket);
        let inner_address = Arc::clone(&address);
        set.spawn(async move {
            let mut buf: [u8; MutableEchoRequestPacket::minimum_packet_size()] =
                [0; MutableEchoRequestPacket::minimum_packet_size()];
            let packet =
                create_icmp_request_packet(&mut buf, i as u16, 1234).consume_to_immutable();
            let now = tokio::time::Instant::now();
            let _sent = inner_socket.send_to(packet.packet(), &Arc::clone(&inner_address));
            let mut buf = [MaybeUninit::new(0);
                EchoReplyPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size()];
            let (_size, address_reply) = read_socket(&inner_socket, &mut buf).await;

            let buf = unsafe {
                #[allow(invalid_value)]
                let mut res: [u8; EchoReplyPacket::minimum_packet_size()
                    + Ipv4Packet::minimum_packet_size()] = MaybeUninit::uninit().assume_init();

                for i in
                    0..EchoReplyPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size()
                {
                    let inner_value = ptr::read(buf[i].as_ptr());

                    res[i] = transmute::<u8, u8>(inner_value);
                }

                res
            };

            let _out_packet = EchoReplyPacket::new(&buf[20..]).unwrap();
            let later = now.elapsed().as_micros();
            println!(
                "{},{},{}",
                address_reply.as_socket().unwrap().ip(),
                i,
                later
            );

            println!("Run Completed\n");
        });
        tokio::time::sleep(Duration::from_millis(input.interval as u64)).await;
    }

    let mut n = 1;
    while let Some(_res) = set.join_next().await {
        println!("{n} Finished!");
        n += 1;
    }
    Ok(())
}

fn get_first_arg() -> Result<String, Box<dyn Error>> {
    match args().nth(1) {
        None => Err(From::from("Expected an argument. None given.")),
        Some(a) => Ok(a),
    }
}

// This shows how you can craft an ICMP request using pnet
// Note that we use pnet only to craft/parse
fn create_icmp_request_packet(
    buf: &mut [u8; MutableEchoRequestPacket::minimum_packet_size()],
    seq: u16,
    identifier: u16,
) -> MutableEchoRequestPacket {
    let mut packet = MutableEchoRequestPacket::new(buf).unwrap();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode(0));
    packet.set_sequence_number(seq);
    packet.set_identifier(identifier);

    let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(packet.packet()).unwrap());
    packet.set_checksum(checksum);

    packet
}

// If you decide to go with the bonus you could just do sock.recv_from(buf).await
async fn read_socket(sock: &Arc<Socket>, buf: &mut [MaybeUninit<u8>]) -> (usize, SockAddr) {
    loop {
        match sock.recv_from(buf) {
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    panic!("Something went wrong while reading the socket");
                }
            }
            Ok(res) => return res,
        }
    }
}

#[allow(dead_code)]
// This function is just here to show you the size of the buffer you need to read ECHO replies.
async fn read_socket_to_buf(
    sock: &Arc<Socket>,
    buf: &mut [MaybeUninit<u8>;
             EchoReplyPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size()],
) {
    let (_res, _addr) = read_socket(&sock, buf).await;
}
