use libc::c_int;
use pnet::packet::{
    icmp::{
        echo_reply::EchoReplyPacket, echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket,
        IcmpTypes,
    },
    ipv4::Ipv4Packet,
    Packet,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use std::{
    env::args,
    error::Error,
    io::ErrorKind,
    mem::{self, transmute, MaybeUninit},
    net::{Ipv4Addr, SocketAddrV4},
    os::fd::AsRawFd,
    ptr,
    sync::Arc,
    time::Duration,
};

const PACKET_SIZE: usize =
    EchoReplyPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size();

#[derive(serde::Deserialize)]
struct InputAddr {
    address: Ipv4Addr,
    count: usize,
    interval: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // parse the input into each value
    let target = get_first_arg()?;
    let record = csv::StringRecord::from(target.split(',').collect::<Vec<_>>());
    let input: InputAddr = record.deserialize(None)?;

    // create the socket to be passed around
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    
    let socket = UdpSocket::bind((input.address, 0)).await?;

    // create the "sockaddr"
    let address = create_sock_address(&socket);

    // set the ip address for the socket to send and recv from
    let mut address = address.as_socket_ipv4().unwrap();
    address.set_ip(input.address);
    let address: SockAddr = address.into();

    // put the socket and address into Arc<> for thread sharing
    let socket = Arc::new(socket);
    let address = Arc::new(address);

    // create a set for the tasks to be collected into
    let mut set = tokio::task::JoinSet::new();

    for i in 0..input.count {
        let inner_socket = Arc::clone(&socket);
        let inner_address = Arc::clone(&address);
        set.spawn(async move {
            // create a buffer for the data to be carried in while sending
            let mut buf: [u8; MutableEchoRequestPacket::minimum_packet_size()] =
                [0; MutableEchoRequestPacket::minimum_packet_size()];
            // create a packet to be sent
            let packet =
                create_icmp_request_packet(&mut buf, i as u16, 1234).consume_to_immutable();

            let now = tokio::time::Instant::now();

            //let _sent = inner_socket.send_to(packet.packet(), &Arc::clone(&inner_address).into::<SocketAddrV4>());
            let bound = Arc::clone(&inner_address).as_socket_ipv4().unwrap();
            let _sent = inner_socket.send_to(packet.packet(), bound);

            // create the buffer to take in the response data
            let mut buf = [MaybeUninit::new(0); PACKET_SIZE];
            //let (_size, address_reply) = read_socket(&inner_socket, &mut buf).await;
            let fut = read_socket(&inner_socket, &mut buf);
            //            let fut = async {
            //                tokio::time::sleep(Duration::from_secs_f64(1.0)).await;
            //                (0usize, inner_address)
            //            };

            let (_size, address_reply) =
                match tokio::time::timeout(tokio::time::Duration::from_secs(1), fut).await {
                    Ok(a) => {
                        println!("Working");
                        a
                    }
                    Err(time) => {
                        println!("Error scheduling the timeout: {}", time);
                        return;
                    }
                };

            let later = now.elapsed().as_micros();

            let buf = extract_data(&mut buf);

            // ignore the first 20 bytes, they are the ipv4 things.
            // the last 8 bytes are the actual ICMP data
            let _out_packet = EchoReplyPacket::new(&buf[20..]).unwrap();

            println!(
                "{},{},{}",
                address_reply.as_socket().unwrap().ip(),
                i,
                later
            );
        });

        // sleep for the interval provided via stdin
        tokio::time::sleep(Duration::from_millis(input.interval as u64)).await;
    }

    // let mut n = 1;
    // join all the tasks
    while let Some(_res) = set.join_next().await {
        // println!("{n} Finished!");
        // n += 1;
    }
    Ok(())
}

fn get_first_arg() -> Result<String, Box<dyn Error>> {
    match args().nth(1) {
        None => Err(From::from("Expected an argument. None given.")),
        Some(a) => Ok(a),
    }
}

fn create_sock_address(socket: &UdpSocket) -> SockAddr {
    // ICMP doesn't have a port and SockAddr requires it.
    // This allows the creation of SockAddr that has no port
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
    address
}

fn extract_data(buf: &mut [MaybeUninit<u8>]) -> [u8; PACKET_SIZE] {
    // converts the slice of MaybeUninit to a [u8] that can be parsed
    // as real bytes
    unsafe {
        #[allow(invalid_value)]
        let mut res: [u8; PACKET_SIZE] = MaybeUninit::uninit().assume_init();

        for i in 0..PACKET_SIZE {
            let inner_value = ptr::read(buf[i].as_ptr());

            res[i] = transmute::<u8, u8>(inner_value);
        }

        res
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
async fn read_socket(sock: &Arc<UdpSocket>, buf: &mut [MaybeUninit<u8>]) -> (usize, SockAddr) {
    loop {
        let mut buf = extract_data(buf);
        match sock.recv_from(&mut buf).await {
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else {
                    panic!("Something went wrong while reading the socket");
                }
            }
            Ok((len, addr)) => {
                println!("inside!");
                return (len, addr.into());
            }
        }
    }
}

// This function is just here to show you the size of the buffer you need to read ECHO replies.
// async fn read_socket_to_buf(
//     sock: &Arc<Socket>,
//     buf: &mut [MaybeUninit<u8>;
//              EchoReplyPacket::minimum_packet_size() + Ipv4Packet::minimum_packet_size()],
// ) {
//     let (_res, _addr) = read_socket(&sock, buf).await;
// }
