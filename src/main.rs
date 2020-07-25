//! This program talks to DNS servers
//! https://en.wikipedia.org/wiki/Domain_Name_System
//! https://tools.ietf.org/html/rfc1035

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate static_assertions;

use std::env;
use std::io;
use std::mem::size_of;
use std::net::UdpSocket;

use rand::Rng;

/// https://tools.ietf.org/html/rfc1035#section-4.1.1
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
struct DnsHeader {
	id: u16,
	flags: u16,
	qcount: u16,
	ancount: u16,
	nscount: u16,
	arcount: u16,
}

const_assert_eq!(size_of::<DnsHeader>(), 12);

bitflags! {
	/// https://tools.ietf.org/html/rfc1035#section-4.1.1
	struct DnsHeaderFlags : u16 {
		const RESPONSE = 0x1;

		const RECURSION_DESIRED = 0x100;
	}
}

/// https://tools.ietf.org/html/rfc1035#section-3.2.2
#[repr(u16)]
#[allow(dead_code)]
enum Type {
	A = 1,
	NS = 2,
	MD = 3,
	MF = 4,
	CNAME = 5,
	SOA = 6,
	MB = 7,
	MG = 8,
	MR = 9,
	NULL = 10,
	WKS = 11,
	PTR = 12,
	HINFO = 13,
	MINFO = 14,
	MX = 15,
	TXT = 16,
}

///https://tools.ietf.org/html/rfc1035#section-3.2.4
#[repr(u16)]
#[allow(dead_code)]
enum Class {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4,
}

fn as_u8_slice<T>(x: &T) -> &[u8] {
	unsafe { std::slice::from_raw_parts(x as *const T as *const u8, size_of::<T>()) }
}

fn hexdump(data: &[u8]) {
	for (i, d) in data.chunks(16).enumerate() {
		print!("{:04x}  ", i * 16);
		for ch in d.chunks(8) {
			for x in ch {
				print!("{:02x} ", x);
			}
			print!(" ");
		}
		println!();
	}
}

fn main() -> io::Result<()> {
	let query = env::args().nth(1).unwrap_or_else(|| {
		println!("No query specified, using default");
		"www.google.com".to_string()
	});
	println!("Query: {}", query);

	let socket = UdpSocket::bind("0.0.0.0:1234")?;

	// Put your router IP here
	socket.connect("192.168.1.254:53")?;

	let buf_size = size_of::<DnsHeader>() + 6 + query.len();
	let mut data = Vec::with_capacity(buf_size);

	let hdr = DnsHeader {
		id: rand::thread_rng().gen_range(0, 63335),
		flags: DnsHeaderFlags::RECURSION_DESIRED.bits().to_be(),
		qcount: 1u16.to_be(),
		..Default::default()
	};

	// Write DNS header
	data.extend_from_slice(as_u8_slice(&hdr));

	// Format query
	// The URL is formatted by splitting it at '.' and replace the '.' with the length in bytes until the next '.'
	for label in query.split('.') {
		data.extend_from_slice(&[label.len() as u8]);
		data.extend_from_slice(label.as_bytes());
	}
	// After the last chunk, there is a zero to show there is no more data.
	data.push(0u8);

	// Write the query type and class
	data.extend_from_slice(&(Type::A as u16).to_be_bytes());
	data.extend_from_slice(&(Class::IN as u16).to_be_bytes());

	println!("Hexdump of DNS request:");
	hexdump(&data);

	println!("Sending request...");
	socket.send(&data)?;
	println!("Request sent.");

	let response = {
		let mut response = vec![0; 4096];
		println!("Waiting for response...");
		let length = socket.recv(&mut response)?;
		println!("Response arrived.");
		response.truncate(length);
		response.into_boxed_slice()
	};

	println!("Hexdump of DNS response:");
	hexdump(&response);

	Ok(())
}
