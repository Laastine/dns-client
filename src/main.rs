#[macro_use]
extern crate bitfield;

use std::convert::TryFrom;
use std::net::UdpSocket;

fn a_record_query(dns_name: &str, transaction_id: (u8, u8)) -> Vec<u8> {
    let mut query: Vec<u8> = vec![
        transaction_id.0,
        transaction_id.1, // Transaction ID
        0x01,
        0x00, // Flags
        0x00,
        0x01, // Questions: 1
        0x00,
        0x00, // Answer RRs
        0x00,
        0x00, // Authority RRs
        0x00,
        0x00, // Additional RRs
    ];
    for b in dns_name.split('.') {
        query.push(b.as_bytes().len() as u8);
        for &c in b.as_bytes() {
            query.push(c)
        }
    }
    query.append(&mut vec![
        0x00, // Null character terminates DNS name
        0x00, 0x01, // Query type A
        0x00, 0x01, // Class IN
    ]);
    query
}

fn query_dns_server() {
    let packet_id: (u8, u8) = (0x07, 0x09);
    let socket = UdpSocket::bind("127.0.0.1:0")
        .unwrap_or_else(|err| panic!("Socket bind error {}", err));
    let query = a_record_query("example.com", packet_id);

    match socket.send_to(&query, "127.0.0.53:53") {
        Ok(number_of_bytes) => println!("Send {} bytes", number_of_bytes),
        Err(fail) => println!("failed sending {:?}", fail),
    };

    let mut res_buf = [0u8; 65527]; // UDP datagram upper limit
    let (number_of_bytes, src_address) = socket
        .recv_from(&mut res_buf)
        .expect("Response read error {}");
    println!("{} bytes received from {} ", number_of_bytes, src_address);
    let filled_buf = &mut res_buf[..number_of_bytes];

    process_server_response(filled_buf.to_vec(), packet_id);
}

bitfield! {
  #[derive(Copy, Clone, Eq, PartialEq)]
  pub struct Header(u16); impl Debug;
  pub qr,                   _: 7, 7;    // Query response
  pub opcode,               _: 6, 6;    // Operation code
  pub aa,                   _: 5, 5;    // Authoritative Answer
  pub tc,                   _: 4, 1;    // Truncated Message
  pub rd,                   _: 0, 0;    // Recursion Desired
  pub rcode,                _: 8, 8;    // Response Code
  pub z,                    _: 11, 9;   // Reserved
  pub ra,                   _: 15, 12;  // Recursion Available
}

bitfield! {
  #[derive(Copy, Clone, Eq, PartialEq)]
  pub struct TTL(u32); impl Debug;
    pub ttl1,               _: 31, 24;
    pub ttl2,               _: 23, 16;
    pub ttl3,               _: 15, 8;
    pub ttl4,               _: 7,  0;
}

fn process_server_response(response: Vec<u8>, msg_id: (u8, u8)) {
    let mut iter = response.iter();
    assert_eq!(
        iter.next(),
        Some(&msg_id.0),
        "first byte of message id missing"
    );
    assert_eq!(
        iter.next(),
        Some(&msg_id.1),
        "second byte of message id missing"
    );

    let h = Header(construct_u16_from_u8(iter.next(), iter.next()));
    println!(
        "QR: {}, OPCODE: {}, AA: {}, TC: {}, RD: {}, RA: {}, Z: {}, RCODE: {}",
        h.qr(),
        h.opcode(),
        h.aa(),
        h.tc(),
        h.rd(),
        h.ra(),
        h.z(),
        h.rcode()
    );

    let qdcount = construct_u16_from_u8(iter.next(), iter.next());
    let ancount = construct_u16_from_u8(iter.next(), iter.next());
    let nscount = construct_u16_from_u8(iter.next(), iter.next());
    let arcount = construct_u16_from_u8(iter.next(), iter.next());
    println!(
        "QDCOUNT: {}\nANCOUNT: {}\nNSCOUNT: {}\nARCOUNT: {}\n",
        qdcount, ancount, nscount, arcount
    );

    let mut name_bytes;
    let mut dns_name = String::new();
    while {
        name_bytes = *iter.next().expect("Next name byte missing");
        name_bytes != 0
    } {
        for _ in 0..name_bytes {
            dns_name.push(*iter.next().expect("Name parsing out of bounds") as char);
        }
        dns_name.push('.');
    }
    println!("QNAME: {}", dns_name);
    let qtype = construct_u16_from_u8(iter.next(), iter.next());
    println!(
        "QTYPE: {:?}",
        RecordType::try_from(qtype).expect("Invalid question type")
    );
    println!(
        "QCLASS: {:?}",
        construct_u16_from_u8(iter.next(), iter.next())
    );

    let rname = construct_u16_from_u8(iter.next(), iter.next());
    println!("RNAME: {}", rname);
    let rtype = construct_u16_from_u8(iter.next(), iter.next());
    println!("RTYPE: {}", rtype);
    let rname = construct_u16_from_u8(iter.next(), iter.next());
    println!("RNAME: {}", rname);
    let ttl = construct_u32_from_u8(iter.next(), iter.next(), iter.next(), iter.next());
    println!("TTL: {}", ttl);

    let rdlength = construct_u16_from_u8(iter.next(), iter.next());
    println!("RDLENGTH: {}", rdlength);

    print!("RESPONSE: ");
    for _ in 0..rdlength {
        print!("{}.", iter.next().expect("Response read error"));
    }
}

fn construct_u16_from_u8(fst: Option<&u8>, snd: Option<&u8>) -> u16 {
    ((*fst.expect("first 8bit missing") as u16) << 8) + *snd.expect("last 8bit missing") as u16
}

fn construct_u32_from_u8(
    fst: Option<&u8>,
    snd: Option<&u8>,
    trd: Option<&u8>,
    frt: Option<&u8>,
) -> u32 {
    ((*fst.expect("first 8bit missing") as u32) << 24)
        + ((*snd.expect("second 8bit missing") as u32) << 16)
        + ((*trd.expect("third 8bit missing") as u32) << 8)
        + *frt.expect("fourth 8bit missing") as u32
}

fn main() {
    query_dns_server();
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl TryFrom<u16> for ResponseCode {
    type Error = &'static str;

    fn try_from(v: u16) -> Result<ResponseCode, Self::Error> {
        match v {
            v if v == ResponseCode::NoError as u16 => Ok(ResponseCode::NoError),
            v if v == ResponseCode::FormatError as u16 => Ok(ResponseCode::FormatError),
            v if v == ResponseCode::ServerFailure as u16 => Ok(ResponseCode::ServerFailure),
            v if v == ResponseCode::NameError as u16 => Ok(ResponseCode::NameError),
            v if v == ResponseCode::NotImplemented as u16 => Ok(ResponseCode::NotImplemented),
            v if v == ResponseCode::Refused as u16 => Ok(ResponseCode::Refused),
            _ => Err("Rcode value not found"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Wks = 11,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
}

impl TryFrom<u16> for RecordType {
    type Error = &'static str;

    fn try_from(v: u16) -> Result<RecordType, Self::Error> {
        match v {
            v if v == RecordType::A as u16 => Ok(RecordType::A),
            v if v == RecordType::Ns as u16 => Ok(RecordType::Ns),
            v if v == RecordType::Cname as u16 => Ok(RecordType::Cname),
            v if v == RecordType::Soa as u16 => Ok(RecordType::Soa),
            v if v == RecordType::Wks as u16 => Ok(RecordType::Wks),
            v if v == RecordType::Ptr as u16 => Ok(RecordType::Ptr),
            v if v == RecordType::Mx as u16 => Ok(RecordType::Mx),
            v if v == RecordType::Txt as u16 => Ok(RecordType::Txt),
            _ => Err("RecordType value not found"),
        }
    }
}
