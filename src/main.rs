use cidr_utils::cidr::Ipv4Cidr;
use cidr_utils::utils::Ipv4CidrCombiner;
use std::env::args;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::from_utf8;

fn main() {
    for asn in args().skip(1) {
        match get_ipv4_by_asn(&asn) {
            Ok(combiner) => {
                println!("{}", combiner);
            }
            Err(err) => {
                eprintln!("while retrieving {}, an error occured: {}", asn, err);
            }
        }
    }
}

fn get_ipv4_by_asn(asn: &str) -> Result<Ipv4CidrCombiner, Box<dyn Error>> {
    const WHOIS_HOST: &str = "whois.radb.net:43";
    let mut stream = TcpStream::connect(WHOIS_HOST)?;
    stream.write_fmt(format_args!("!gAS{}\r\n", asn))?;
    stream.flush()?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut header = String::new();
    reader.read_line(&mut header)?;

    const SPACE: u8 = b' ';
    let mut combiner = Ipv4CidrCombiner::new();
    let mut addr: Vec<u8> = vec![];
    while reader.read_until(SPACE, &mut addr)? != 0 {
        let mut addr_str = from_utf8(&addr[..addr.len() - 1])?;

        // the last item ends with new line, not space
        if addr.last().unwrap_or(&0) != &SPACE {
            // remove everything after the new line
            addr_str = addr_str.split_ascii_whitespace().next().unwrap_or("");
        }

        combiner.push(Ipv4Cidr::from_str(addr_str)?);
        addr.clear();
    }
    Ok(combiner)
}
