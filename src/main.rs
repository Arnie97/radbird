use cidr_utils::cidr::Ipv4Cidr;
use cidr_utils::utils::Ipv4CidrCombiner;
use std::env::args;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::from_utf8;

fn main() {
    dbg!(args());

    const WHOIS_HOST: &str = "whois.radb.net:43";
    let mut stream = TcpStream::connect(WHOIS_HOST).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut header = String::new();
    stream.write_all(b"!gAS133119\r\n").unwrap();
    stream.flush().unwrap();
    reader.read_line(&mut header).unwrap();
    dbg!(header);

    let mut combiner = Ipv4CidrCombiner::new();
    let mut addr: Vec<u8> = vec![];
    while reader.read_until(b' ', &mut addr).unwrap() != 0 {
        let mut addr_str = from_utf8(&addr[..addr.len() - 1]).unwrap();
        if addr.last().unwrap() != &b' ' {
            addr_str = addr_str.split_ascii_whitespace().next().unwrap();
        }
        match Ipv4Cidr::from_str(addr_str) {
            Ok(cidr) => combiner.push(cidr),
            Err(err) => {
                dbg!(err, addr_str);
            }
        }
        addr.clear();
    }
    dbg!(combiner);
}
