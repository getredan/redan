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
    // DNS header: 12 bytes minimum
    if packet.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);

    // Must be a standard query (QR=0, OPCODE=0)
    if flags & 0x8000 != 0 {
        return None; // Response, not query
    }
    if flags & 0x7800 != 0 {
        return None; // Non-standard opcode
    }
    if qd_count == 0 {
        return None;
    }

    // Parse the first question
    let (qname, qname_end) = parse_qname(packet, 12)?;
    if qname_end + 4 > packet.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([packet[qname_end], packet[qname_end + 1]]);
    let qclass = u16::from_be_bytes([packet[qname_end + 2], packet[qname_end + 3]]);

    // Only handle IN class
    if qclass != 1 {
        return None;
    }

    let hostname = qname.trim_end_matches('.').to_string();

    match qtype {
        1 => {
            // A record: respond with gateway IP
            let response = build_a_response(id, packet, qname_end + 4, gateway_ip);
            Some((hostname, response))
        }
        28 => {
            // AAAA record: respond with NOERROR, zero answers
            let response = build_empty_response(id, packet, qname_end + 4);
            Some((hostname, response))
        }
        _ => {
            // Anything else: NOERROR, zero answers
            let response = build_empty_response(id, packet, qname_end + 4);
            Some((hostname, response))
        }
    }
}

/// Parse a DNS name from wire format into a dotted string.
/// Returns the name and the byte offset past the end of the name.
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

        // Compression pointer (top 2 bits set) -- shouldn't appear in queries
        // but handle gracefully
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return None;
            }
            // We don't follow pointers for the spike; just bail
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

/// Build a DNS response with one A record pointing at the gateway IP.
fn build_a_response(
    id: u16,
    query: &[u8],
    question_end: usize,
    ip: Ipv4Address,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end + 16);

    // Header
    resp.extend_from_slice(&id.to_be_bytes()); // Transaction ID
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question section (copy from query)
    resp.extend_from_slice(&query[12..question_end]);

    // Answer section: pointer to name in question + A record
    resp.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Name pointer to offset 12
    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    resp.extend_from_slice(&ip.octets()); // RDATA = gateway IP

    resp
}

/// Build a DNS response with zero answers (NOERROR).
fn build_empty_response(id: u16, query: &[u8], question_end: usize) -> Vec<u8> {
    let mut resp = Vec::with_capacity(question_end);

    // Header
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    // Question section (copy from query)
    resp.extend_from_slice(&query[12..question_end]);

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS A query for a hostname.
    fn build_query(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&id.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // QNAME
        for label in hostname.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // Root label

        // QTYPE + QCLASS
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN

        pkt
    }

    #[test]
    fn test_a_record_resolves_to_gateway() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0x1234, "httpbin.org", 1);

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "httpbin.org");

        // Check response header
        assert_eq!(response[0..2], 0x1234u16.to_be_bytes()); // ID matches
        assert_eq!(response[2] & 0x80, 0x80); // QR=1 (response)
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1); // ANCOUNT=1

        // Check the A record data at the end
        let ip_offset = response.len() - 4;
        assert_eq!(&response[ip_offset..], &[192, 168, 127, 1]);
    }

    #[test]
    fn test_aaaa_returns_empty() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0xABCD, "example.com", 28); // AAAA

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "example.com");
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0); // ANCOUNT=0
    }

    #[test]
    fn test_subdomain_resolution() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let query = build_query(0x0001, "api.github.com", 1);

        let (hostname, response) = handle_query(&query, gw).unwrap();
        assert_eq!(hostname, "api.github.com");

        let ip_offset = response.len() - 4;
        assert_eq!(&response[ip_offset..], &[192, 168, 127, 1]);
    }

    #[test]
    fn test_rejects_response_packets() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        let mut query = build_query(0x1234, "example.com", 1);
        query[2] |= 0x80; // Set QR bit (make it a response)

        assert!(handle_query(&query, gw).is_none());
    }

    #[test]
    fn test_rejects_truncated_packet() {
        let gw = Ipv4Address::new(192, 168, 127, 1);
        assert!(handle_query(&[0; 5], gw).is_none());
    }
}
