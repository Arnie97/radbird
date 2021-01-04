use cidr_utils::{cidr::Ipv4Cidr, utils::Ipv4CidrCombiner};
use std::env::args;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::str::from_utf8;

fn main() {
    for asn in args().skip(1) {
        match print_static_routes(&asn) {
            Ok(_) => continue,
            Err(err) => {
                eprintln!("while retrieving {}, an error occured: {}", asn, err);
            }
        }
    }
}

fn print_static_routes(asn: &str) -> Result<(), Box<dyn Error>> {
    println!("\n#{}", get_desc_by_asn(asn)?);
    for cidr in get_ipv4_by_asn(asn)?.iter() {
        println!(
            r#"route {:17} via "lo" {{ bgp_path.prepend({}); }};"#,
            cidr.to_string(),
            asn
        )
    }
    Ok(())
}

fn get_radb_whois(query: &str) -> Result<BufReader<TcpStream>, Box<dyn Error>> {
    const WHOIS_HOST: &str = "whois.radb.net:43";
    let mut stream = TcpStream::connect(WHOIS_HOST)?;
    stream.write_all(query.as_bytes())?;
    stream.flush()?;
    Ok(BufReader::new(stream))
}

fn get_desc_by_asn(asn: &str) -> Result<String, Box<dyn Error>> {
    let mut line = String::new();
    let mut desc = String::new();
    let mut reader = get_radb_whois(&format!("AS{}\r\n", asn))?;
    while reader.read_line(&mut line)? != 0 {
        let mut pair = line.splitn(2, ":");
        let key = pair.next().ok_or("invalid key")?;
        if key.len() <= 1 {
            return Ok(desc);
        }

        let value = pair.next().ok_or("invalid value")?.trim();
        match key {
            "aut-num" | "as-name" => write!(desc, " {}", value)?,
            "descr" => write!(desc, r#" "{}""#, value)?,
            _ => continue,
        };

        line.clear();
    }
    Ok(desc)
}

fn get_ipv4_by_asn(asn: &str) -> Result<Ipv4CidrCombiner, Box<dyn Error>> {
    let mut header = String::new();
    let mut reader = get_radb_whois(&format!("!gAS{}\r\n", asn))?;
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
