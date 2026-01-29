/// Synthetic DNS resolver.
///
/// All A record queries resolve to the gateway IP. AAAA queries get an empty
/// response (NOERROR, zero answers). This forces all guest traffic through
/// the MITM proxy and prevents DNS exfiltration.
use smoltcp::wire::Ipv4Address;

/// Parse a DNS query and build a synthetic response.
///
/// Returns `Some((hostname, response_bytes))` on success, `None` if the
/// packet is malformed or not a query we handle.
pub fn handle_query(packet: &[u8], gateway_ip: Ipv4Address) -> Option<(String, Vec<u8>)> {
    if packet.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);

    // Must be a standard query (QR=0, OPCODE=0)
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || qd_count == 0 {
        return None;
    }

    let (qname, qname_end) = parse_qname(packet, 12)?;
    if qname_end + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[qname_end], packet[qname_end + 1]]);
    let qclass = u16::from_be_bytes([packet[qname_end + 2], packet[qname_end + 3]]);

    if qclass != 1 {
        return None; // Only IN class
    }

    let hostname = qname.trim_end_matches('.').to_string();
    let question_end = qname_end + 4;

    let response = match qtype {
        1 => build_a_response(id, packet, question_end, gateway_ip),
        _ => build_empty_response(id, packet, question_end),
    };

    Some((hostname, response))
}

/// Parse a DNS name from wire format into a dotted string.
fn parse_qname(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointers shouldn't appear in queries from stub resolvers
        if len & 0xC0 == 0xC0 {
            return None;
        }
        if pos + 1 + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label.to_string());
        pos += 1 + len;
    }

    if labels.is_empty() {
        return None;
    }

    Some((labels.join("."), pos))
}

fn build_a_response(id: u16, query: &[u8], question_end: usize, ip: Ipv4Address) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end + 16);

    // Header
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (copy from query)
    resp.extend_from_slice(&query[12..question_end]);

    // Answer: pointer to name + A record
    resp.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Name pointer to offset 12
    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    resp.extend_from_slice(&ip.octets());

    resp
}

fn build_empty_response(id: u16, query: &[u8], question_end: usize) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end);

    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    resp.extend_from_slice(&query[12..question_end]);

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());

        for label in hostname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);

        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        pkt
    }

    #[test]
    fn a_record_resolves_to_gateway() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0x1234, "httpbin.org", 1);

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "httpbin.org");
        assert_eq!(response[0..2], 0x1234u16.to_be_bytes());
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1); // ANCOUNT

        let ip_offset = response.len() - 4;
        assert_eq!(&response[ip_offset..], &[192, 168, 127, 1]);
    }

    #[test]
    fn aaaa_returns_empty() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0xABCD, "example.com", 28);

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn subdomain_resolution() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0x0001, "api.github.com", 1);

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "api.github.com");
        let ip_offset = response.len() - 4;
        assert_eq!(&response[ip_offset..], &[192, 168, 127, 1]);
    }

    #[test]
    fn rejects_response_packets() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let mut query = build_query(0x1234, "example.com", 1);
        query[2] |= 0x80;
        assert!(handle_query(&query, gw).is_none());
    }

    #[test]
    fn rejects_truncated_packet() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        assert!(handle_query(&[0; 5], gw).is_none());
    }
}
