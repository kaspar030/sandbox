//! Raw netlink socket implementation for network configuration.
//!
//! This provides a minimal netlink ROUTE socket for creating/configuring
//! network interfaces without depending on rtnetlink or shelling out to `ip`.

use crate::error::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Netlink message types (from linux/rtnetlink.h)
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
#[allow(dead_code)]
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;

// Netlink flags
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_EXCL: u16 = 0x0200;

// Netlink message header
const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Interface info attributes (from linux/if_link.h)
const IFLA_IFNAME: u16 = 3;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
#[allow(dead_code)]
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;

// VETH specific
const VETH_INFO_PEER: u16 = 1;

// Address attributes (from linux/if_addr.h)
const IFA_LOCAL: u16 = 2;
const IFA_ADDRESS: u16 = 1;

// Route attributes
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;

// Interface flags
const IFF_UP: u32 = 0x1;

/// A raw netlink socket for NETLINK_ROUTE operations.
pub struct NetlinkSocket {
    fd: OwnedFd,
    seq: u32,
}

impl NetlinkSocket {
    /// Create a new netlink route socket.
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(Error::Netlink(std::io::Error::last_os_error()));
        }

        let sock = Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            seq: 1,
        };

        // Bind
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // nl_pad, nl_pid, nl_groups are all zero from zeroed()

        let ret = unsafe {
            libc::bind(
                sock.fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            return Err(Error::Netlink(std::io::Error::last_os_error()));
        }

        Ok(sock)
    }

    /// Send a netlink message and wait for ACK.
    fn send_and_ack(&mut self, msg: &[u8]) -> Result<()> {
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(Error::Netlink(std::io::Error::last_os_error()));
        }

        self.recv_ack()
    }

    /// Receive and process ACK response.
    fn recv_ack(&self) -> Result<()> {
        let mut buf = [0u8; 4096];
        let len = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if len < 0 {
            return Err(Error::Netlink(std::io::Error::last_os_error()));
        }

        let len = len as usize;
        if len < NLMSG_HDRLEN {
            return Err(Error::Netlink(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "netlink response too short",
            )));
        }

        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        if msg_type == NLMSG_ERROR {
            let error_code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if error_code == 0 {
                return Ok(()); // ACK (no error)
            }
            return Err(Error::Netlink(std::io::Error::from_raw_os_error(
                -error_code,
            )));
        }

        if msg_type == NLMSG_DONE {
            return Ok(());
        }

        Ok(())
    }

    /// Get the interface index for a given name.
    pub fn get_link_index(&self, name: &str) -> Result<u32> {
        let idx = unsafe { libc::if_nametoindex(std::ffi::CString::new(name).unwrap().as_ptr()) };
        if idx == 0 {
            return Err(Error::Netlink(std::io::Error::last_os_error()));
        }
        Ok(idx)
    }

    /// Create a veth pair.
    pub fn create_veth(&mut self, name: &str, peer_name: &str) -> Result<()> {
        let mut msg = NetlinkMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        msg.seq = self.seq;
        self.seq += 1;

        // ifinfomsg (16 bytes)
        let ifinfo = [0u8; 16];
        msg.extend_payload(&ifinfo);

        // IFLA_IFNAME
        msg.add_attr(IFLA_IFNAME, name.as_bytes());

        // IFLA_LINKINFO (nested)
        let linkinfo_start = msg.start_nested_attr(IFLA_LINKINFO);
        msg.add_attr(IFLA_INFO_KIND, b"veth");

        // IFLA_INFO_DATA -> VETH_INFO_PEER (nested)
        let info_data_start = msg.start_nested_attr(IFLA_INFO_DATA);
        let peer_start = msg.start_nested_attr(VETH_INFO_PEER);

        // peer ifinfomsg
        msg.extend_payload(&[0u8; 16]);
        msg.add_attr(IFLA_IFNAME, peer_name.as_bytes());

        msg.end_nested_attr(peer_start);
        msg.end_nested_attr(info_data_start);
        msg.end_nested_attr(linkinfo_start);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Move an interface to another network namespace by PID.
    pub fn set_link_netns(&mut self, name: &str, pid: libc::pid_t) -> Result<()> {
        let idx = self.get_link_index(name)?;

        let mut msg = NetlinkMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        msg.seq = self.seq;
        self.seq += 1;

        // ifinfomsg with the interface index
        let mut ifinfo = [0u8; 16];
        // ifi_index at offset 4
        ifinfo[4..8].copy_from_slice(&(idx as i32).to_ne_bytes());
        msg.extend_payload(&ifinfo);

        // IFLA_NET_NS_PID
        msg.add_attr_u32(IFLA_NET_NS_PID, pid as u32);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Set a link up.
    pub fn set_link_up(&mut self, idx: u32) -> Result<()> {
        let mut msg = NetlinkMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        msg.seq = self.seq;
        self.seq += 1;

        // ifinfomsg: set IFF_UP
        let mut ifinfo = [0u8; 16];
        // ifi_family at offset 0 (AF_UNSPEC = 0)
        // ifi_type at offset 2 (0)
        // ifi_index at offset 4
        ifinfo[4..8].copy_from_slice(&(idx as i32).to_ne_bytes());
        // ifi_flags at offset 8: IFF_UP
        ifinfo[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
        // ifi_change at offset 12: IFF_UP (change mask)
        ifinfo[12..16].copy_from_slice(&IFF_UP.to_ne_bytes());
        msg.extend_payload(&ifinfo);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Set a link up by name.
    pub fn set_link_up_by_name(&mut self, name: &str) -> Result<()> {
        let idx = self.get_link_index(name)?;
        self.set_link_up(idx)
    }

    /// Delete a link.
    pub fn delete_link(&mut self, name: &str) -> Result<()> {
        let idx = self.get_link_index(name)?;

        let mut msg = NetlinkMsg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
        msg.seq = self.seq;
        self.seq += 1;

        let mut ifinfo = [0u8; 16];
        ifinfo[4..8].copy_from_slice(&(idx as i32).to_ne_bytes());
        msg.extend_payload(&ifinfo);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Create a bridge interface.
    pub fn create_bridge(&mut self, name: &str) -> Result<()> {
        let mut msg = NetlinkMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        msg.seq = self.seq;
        self.seq += 1;

        let ifinfo = [0u8; 16];
        msg.extend_payload(&ifinfo);

        msg.add_attr(IFLA_IFNAME, name.as_bytes());

        let linkinfo_start = msg.start_nested_attr(IFLA_LINKINFO);
        msg.add_attr(IFLA_INFO_KIND, b"bridge");
        msg.end_nested_attr(linkinfo_start);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Add an interface to a bridge.
    pub fn set_master(&mut self, iface_name: &str, bridge_name: &str) -> Result<()> {
        let iface_idx = self.get_link_index(iface_name)?;
        let bridge_idx = self.get_link_index(bridge_name)?;

        let mut msg = NetlinkMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
        msg.seq = self.seq;
        self.seq += 1;

        let mut ifinfo = [0u8; 16];
        ifinfo[4..8].copy_from_slice(&(iface_idx as i32).to_ne_bytes());
        msg.extend_payload(&ifinfo);

        msg.add_attr_u32(IFLA_MASTER, bridge_idx);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Add an IP address to an interface.
    pub fn add_address(
        &mut self,
        iface_idx: u32,
        addr: std::net::Ipv4Addr,
        prefix_len: u8,
    ) -> Result<()> {
        let mut msg = NetlinkMsg::new(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        msg.seq = self.seq;
        self.seq += 1;

        // ifaddrmsg (8 bytes)
        let mut ifaddr = [0u8; 8];
        ifaddr[0] = libc::AF_INET as u8; // ifa_family
        ifaddr[1] = prefix_len;           // ifa_prefixlen
        ifaddr[2] = 0;                    // ifa_flags
        ifaddr[3] = 0;                    // ifa_scope (RT_SCOPE_UNIVERSE)
        ifaddr[4..8].copy_from_slice(&(iface_idx as i32).to_ne_bytes()); // ifa_index
        msg.extend_payload(&ifaddr);

        let addr_bytes = addr.octets();
        msg.add_attr(IFA_LOCAL, &addr_bytes);
        msg.add_attr(IFA_ADDRESS, &addr_bytes);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }

    /// Add a default route via a gateway.
    pub fn add_default_route(&mut self, gateway: std::net::Ipv4Addr, oif: u32) -> Result<()> {
        let mut msg = NetlinkMsg::new(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        msg.seq = self.seq;
        self.seq += 1;

        // rtmsg (12 bytes)
        let mut rtmsg = [0u8; 12];
        rtmsg[0] = libc::AF_INET as u8;  // rtm_family
        rtmsg[1] = 0;                     // rtm_dst_len (0 = default route)
        rtmsg[2] = 0;                     // rtm_src_len
        rtmsg[3] = 0;                     // rtm_tos
        rtmsg[4] = libc::RT_TABLE_MAIN as u8; // rtm_table
        rtmsg[5] = libc::RTPROT_BOOT as u8;   // rtm_protocol
        rtmsg[6] = libc::RT_SCOPE_UNIVERSE as u8; // rtm_scope
        rtmsg[7] = libc::RTN_UNICAST as u8;       // rtm_type
        rtmsg[8..12].copy_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        msg.extend_payload(&rtmsg);

        let gw_bytes = gateway.octets();
        msg.add_attr(RTA_GATEWAY, &gw_bytes);
        msg.add_attr_u32(RTA_OIF, oif);

        let data = msg.finalize();
        self.send_and_ack(&data)
    }
}

/// Helper for building netlink messages.
struct NetlinkMsg {
    buf: Vec<u8>,
    msg_type: u16,
    flags: u16,
    seq: u32,
}

impl NetlinkMsg {
    fn new(msg_type: u16, flags: u16) -> Self {
        Self {
            buf: Vec::with_capacity(256),
            msg_type,
            flags,
            seq: 0,
        }
    }

    fn extend_payload(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Add a netlink attribute with raw data.
    fn add_attr(&mut self, attr_type: u16, data: &[u8]) {
        let attr_len = 4 + data.len(); // nla_len (2) + nla_type (2) + data
        let padded_len = (attr_len + 3) & !3; // align to 4 bytes

        self.buf.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);

        // Pad with zeros
        let padding = padded_len - attr_len;
        self.buf.extend(std::iter::repeat(0u8).take(padding));
    }

    /// Add a u32 attribute.
    fn add_attr_u32(&mut self, attr_type: u16, value: u32) {
        self.add_attr(attr_type, &value.to_ne_bytes());
    }

    /// Start a nested attribute, returns the position to fill in the length later.
    fn start_nested_attr(&mut self, attr_type: u16) -> usize {
        let pos = self.buf.len();
        // Placeholder for nla_len
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(attr_type | 0x8000).to_ne_bytes()); // NLA_F_NESTED
        pos
    }

    /// End a nested attribute, filling in the length.
    fn end_nested_attr(&mut self, start_pos: usize) {
        let len = (self.buf.len() - start_pos) as u16;
        self.buf[start_pos..start_pos + 2].copy_from_slice(&len.to_ne_bytes());
        // Pad to 4-byte alignment
        let padding = ((self.buf.len() + 3) & !3) - self.buf.len();
        self.buf.extend(std::iter::repeat(0u8).take(padding));
    }

    /// Finalize the message by prepending the nlmsghdr.
    fn finalize(self) -> Vec<u8> {
        let total_len = NLMSG_HDRLEN + self.buf.len();
        let mut msg = Vec::with_capacity(total_len);

        // nlmsghdr
        msg.extend_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&self.msg_type.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&self.flags.to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&self.seq.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid

        msg.extend_from_slice(&self.buf);

        msg
    }
}
