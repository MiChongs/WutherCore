//! 公共：SOCKS5/Trojan/Shadowsocks 通用的"目标地址"编码。
//!
//! 三个协议都用同一种格式：ATYP(1) + ADDR(变长) + PORT(2 BE)。

use std::io;

use bytes::BufMut;

#[derive(Debug, Clone)]
pub enum Address<'a> {
    Domain(&'a str),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl<'a> Address<'a> {
    pub fn parse(host: &'a str) -> Self {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Address::Ipv4(ip.octets());
        }
        if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            return Address::Ipv6(ip.octets());
        }
        Address::Domain(host)
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Domain(d) => 1 + 1 + d.len() + 2,
            Self::Ipv4(_) => 1 + 4 + 2,
            Self::Ipv6(_) => 1 + 16 + 2,
        }
    }

    pub fn encode(&self, port: u16, out: &mut Vec<u8>) {
        match self {
            Self::Ipv4(b) => {
                out.put_u8(0x01);
                out.extend_from_slice(b);
            }
            Self::Domain(d) => {
                let bytes = d.as_bytes();
                let len = bytes.len().min(255);
                out.put_u8(0x03);
                out.put_u8(len as u8);
                out.extend_from_slice(&bytes[..len]);
            }
            Self::Ipv6(b) => {
                out.put_u8(0x04);
                out.extend_from_slice(b);
            }
        }
        out.put_u16(port);
    }
}

pub fn encode_socks_addr(host: &str, port: u16) -> Vec<u8> {
    let a = Address::parse(host);
    let mut buf = Vec::with_capacity(a.encoded_len());
    a.encode(port, &mut buf);
    buf
}

pub fn decode_socks_addr(buf: &[u8]) -> io::Result<(String, u16, usize)> {
    if buf.is_empty() {
        return Err(io_err("missing socks address type"));
    }
    match buf[0] {
        0x01 => {
            if buf.len() < 1 + 4 + 2 {
                return Err(io_err("truncated ipv4 socks address"));
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((ip.to_string(), port, 7))
        }
        0x03 => {
            if buf.len() < 2 {
                return Err(io_err("truncated domain socks address"));
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(io_err("truncated domain socks address body"));
            }
            let host = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| io_err("invalid domain socks address"))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((host, port, 2 + len + 2))
        }
        0x04 => {
            if buf.len() < 1 + 16 + 2 {
                return Err(io_err("truncated ipv6 socks address"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((ip.to_string(), port, 19))
        }
        _ => Err(io_err("unsupported socks address type")),
    }
}

fn io_err(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
