//! Minimal async DNS responder for inter-container name resolution within stacks.
//!
//! Listens on the stack's bridge gateway IP:53 (UDP). Resolves stack-internal
//! service names to container IPs. Forwards all other queries to upstream DNS.
//!
//! DNS packet parsing is minimal — only handles standard A record queries.

use async_io::Async;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Run the DNS responder as an async task.
///
/// Listens on `listen_addr` (gateway:53), resolves names from `names` map,
/// forwards unknown queries to `upstream`. Exits when `shutdown` receives.
pub async fn run_dns_responder(
    listen_addr: SocketAddr,
    names: HashMap<String, Ipv4Addr>,
    upstream: SocketAddr,
    shutdown: smol::channel::Receiver<()>,
) {
    let socket = match Async::<UdpSocket>::bind(listen_addr) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("DNS responder: bind {listen_addr}: {e}");
            return;
        }
    };

    tracing::info!("DNS responder listening on {listen_addr}");
    let mut buf = [0u8; 512];

    loop {
        let result = smol::future::race(
            async {
                let r = socket.recv_from(&mut buf).await;
                Some(r)
            },
            async {
                let _ = shutdown.recv().await;
                None
            },
        )
        .await;

        let (len, src) = match result {
            Some(Ok((len, src))) => (len, src),
            Some(Err(e)) => {
                tracing::debug!("DNS recv error: {e}");
                continue;
            }
            None => {
                tracing::info!("DNS responder shutting down");
                break;
            }
        };

        let query = &buf[..len];
        if query.len() < 12 {
            continue; // too short for DNS header
        }

        // Parse the query name
        if let Some(qname) = parse_query_name(query) {
            // Strip trailing dot if present
            let lookup = qname.trim_end_matches('.');

            // Check if this is a stack-internal name
            if let Some(&ip) = names.get(lookup) {
                // Build and send A record response
                if let Some(response) = build_a_response(query, ip) {
                    let _ = socket.send_to(&response, src).await;
                }
                continue;
            }
        }

        // Forward to upstream DNS
        match forward_query(&socket, query, upstream).await {
            Ok(response) => {
                let _ = socket.send_to(&response, src).await;
            }
            Err(e) => {
                tracing::debug!("DNS forward error: {e}");
                // Send SERVFAIL response
                if let Some(response) = build_servfail(query) {
                    let _ = socket.send_to(&response, src).await;
                }
            }
        }
    }
}

/// Parse the query name from a DNS packet.
/// Returns the decoded domain name (e.g., "db" or "web.mystack").
fn parse_query_name(packet: &[u8]) -> Option<String> {
    let mut pos = 12; // skip header
    let mut name = String::new();

    loop {
        if pos >= packet.len() {
            return None;
        }
        let label_len = packet[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len > packet.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&packet[pos..pos + label_len]));
        pos += label_len;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Build a DNS A record response for a given query and IP address.
fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut response = Vec::with_capacity(query.len() + 16);

    // Copy header
    response.extend_from_slice(&query[..2]); // ID
    // Flags: QR=1 (response), AA=1 (authoritative), RCODE=0 (no error)
    response.extend_from_slice(&[0x85, 0x00]); // flags
    response.extend_from_slice(&query[4..6]); // QDCOUNT (copy from query)
    response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Copy question section
    let question_end = find_question_end(query)?;
    response.extend_from_slice(&query[12..question_end]);

    // Answer section
    response.extend_from_slice(&[0xC0, 0x0C]); // NAME: pointer to offset 12 (question name)
    response.extend_from_slice(&[0x00, 0x01]); // TYPE = A
    response.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60 seconds
    response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    response.extend_from_slice(&ip.octets()); // RDATA = IP address

    Some(response)
}

/// Build a SERVFAIL response for a query.
fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let mut response = Vec::with_capacity(query.len());
    response.extend_from_slice(&query[..2]); // ID
    response.extend_from_slice(&[0x85, 0x02]); // QR=1, AA=1, RCODE=2 (SERVFAIL)
    response.extend_from_slice(&query[4..6]); // QDCOUNT
    response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Copy question section
    if let Some(end) = find_question_end(query) {
        response.extend_from_slice(&query[12..end]);
    }

    Some(response)
}

/// Find the end of the question section in a DNS packet.
fn find_question_end(packet: &[u8]) -> Option<usize> {
    let mut pos = 12;
    // Skip QNAME (label-encoded)
    loop {
        if pos >= packet.len() {
            return None;
        }
        let label_len = packet[pos] as usize;
        if label_len == 0 {
            pos += 1; // skip the zero byte
            break;
        }
        pos += 1 + label_len;
    }
    pos += 4; // skip QTYPE (2) + QCLASS (2)
    if pos > packet.len() {
        None
    } else {
        Some(pos)
    }
}

/// Forward a DNS query to an upstream resolver and return the response.
async fn forward_query(
    _local_socket: &Async<UdpSocket>,
    query: &[u8],
    upstream: SocketAddr,
) -> std::io::Result<Vec<u8>> {
    // Use a separate socket for forwarding (so we don't mix up responses)
    let fwd_socket =
        Async::<UdpSocket>::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))?;
    fwd_socket.send_to(query, upstream).await?;

    let mut buf = [0u8; 512];
    // Wait for response with a timeout
    smol::future::race(
        async {
            let (len, _) = fwd_socket.recv_from(&mut buf).await?;
            Ok(buf[..len].to_vec())
        },
        async {
            smol::Timer::after(std::time::Duration::from_secs(5)).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "DNS forward timeout",
            ))
        },
    )
    .await
}

/// Parse upstream DNS server from /etc/resolv.conf.
pub fn parse_upstream_dns() -> Option<SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(ip_str) = line.strip_prefix("nameserver") {
            let ip_str = ip_str.trim();
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                return Some(SocketAddr::new(ip.into(), 53));
            }
        }
    }
    // Fallback to Google DNS
    Some(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53))
}
