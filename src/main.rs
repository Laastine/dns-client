
use std::net::UdpSocket;


fn query_dns_server() -> Vec<u8> {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap_or_else(|err| panic!("Socket bind error {}", err));
    let query: &[u8] = &[
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query with recursion
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        // Query for example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // Null terminator of the domain name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ];

    dbg!(query);

    match socket.send_to(query, "8.8.8.8:53")  {
        Ok(number_of_bytes) => println!("{:?}", number_of_bytes),
        Err(fail) => println!("failed sending {:?}", fail),
    }

    let mut res = [0u8; 512];

    let (_size, _src) = socket.recv_from(&mut res).unwrap_or_else(|_| panic!("response read error"));

    res.to_vec()
}

fn main() {

    let res  = query_dns_server();

    println!("Result: {:?}", res);
}
