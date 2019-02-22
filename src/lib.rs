#![allow(dead_code)]
use std::net::TcpStream;
use std::io::prelude::*;
use std::error::Error;

use log::{info, debug, error};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use simple_error::bail;
use sha1;
use sha1::Digest;

pub struct Hpfeeds {
    pub ident: String,
    pub secret: String,
    pub broker_name: String,
    sock: TcpStream,
}

impl Hpfeeds {
    pub fn new(host: &str, port: u32, ident: &str, secret: &str) -> Result<Hpfeeds, Box<Error>> {
        let mut s = TcpStream::connect(format!("{}:{}", host, port))?;
        let mut buf_info = vec![0u8; 1024];
        let c_info_read = s.read(&mut buf_info)?;
        let buf_info = &buf_info[..c_info_read];

        let info_msg = handle_recv(buf_info)?;
        let (bn, nonce) = match info_msg {
            HpfeedsMsg::InfoMsg(hdr, bn, nonce) => {
                (bn, nonce)
            },
            _ => bail!("First packet was not OP_INFO."),
        };

        send_authenticate(&s, ident, &nonce, secret)?;
        Ok(Hpfeeds {
            ident: ident.to_owned(),
            secret: secret.to_owned(),
            broker_name: bn,
            sock: s,
        })
    }

    pub fn publish_to(&self, channel: &str, payload: &[u8]) -> Result<(), Box<Error>> {
        send_publish(&self.sock, &self.ident, channel, payload)?;
        Ok(())
    }
}

pub struct HpfeedsHdr {
    pub len: u32,
    pub opcode: u8,
}

pub enum HpfeedsMsg {
    ErrorMsg(HpfeedsHdr, String),
    InfoMsg(HpfeedsHdr, String, Vec<u8>),
}

pub fn handle_recv(data: &[u8]) -> Result<HpfeedsMsg, Box<Error>>{
    let mut b_len = &data[..4];
    let len = b_len.read_u32::<BigEndian>().unwrap();
    let opcode = data[4];
    let payload = &data[5..];
    let header = HpfeedsHdr{len: len, opcode: opcode};

    match opcode {
        0x00 => parse_error(header, payload),
        0x01 => parse_info(header, payload),
        _ => bail!("Couldnt parse message from server"),
    }
}

pub fn parse_error(hdr: HpfeedsHdr, payload: &[u8]) -> Result<HpfeedsMsg, Box<Error>> {
    let r = String::from_utf8_lossy(payload);
    Ok(HpfeedsMsg::ErrorMsg(hdr, r.to_string()))
}

pub fn parse_info(hdr: HpfeedsHdr, payload: &[u8]) -> Result<HpfeedsMsg, Box<Error>> {
    let c_broker_name = payload[0] as usize;
    let broker_name = String::from_utf8_lossy(&payload[1..=c_broker_name]);
    let nonce = &payload[c_broker_name+1..];
    Ok(HpfeedsMsg::InfoMsg(hdr, broker_name.to_string(), Vec::from(nonce)))
}

pub fn send_publish(conn: &TcpStream, ident: &str, channel: &str, data: &[u8]) -> Result<(), Box<Error>>{
    let mut buf: Vec<u8> = Vec::new();
    buf.push(ident.len() as u8);
    buf.extend_from_slice(ident.as_bytes());
    buf.push(channel.len() as u8);
    buf.extend_from_slice(channel.as_bytes());
    buf.extend_from_slice(data);
    
    match send_raw(conn, 0x03, &buf) {
        Ok(_) => {
            info!("Successfully sent publish");
            Ok(())
        },
        Err(e) => bail!(e),
    }
}

pub fn send_authenticate(conn: &TcpStream, ident: &str, nonce: &[u8], secret: &str) -> Result<(), Box<Error>> {
    let mut s: sha1::Sha1 = sha1::Digest::new();
    s.input(nonce);
    s.input(secret.as_bytes());
    let digest = s.result();

    // construct message
    let mut auth_msg: Vec<u8> = Vec::new();
    auth_msg.push(ident.len() as u8);
    auth_msg.extend_from_slice(ident.as_bytes());
    auth_msg.extend_from_slice(&digest);
    match send_raw(conn, 0x02, &auth_msg) {
        Ok(_) => {
            info!("Successfully sent auth");
        },
        Err(e) => bail!(e),
    }
    
    Ok(())
}

fn send_raw(conn: &TcpStream, opcode: u8, data: &[u8]) -> Result<(), Box<Error>> {
    let len: u32 = (data.len() as u32) + 5;
    let mut buf: Vec<u8> = Vec::new();
    
    buf.write_u32::<BigEndian>(len).unwrap();
    buf.push(opcode as u8);
    buf.extend_from_slice(data);
    let mut conn = conn.try_clone()?;
    conn.write_all(&buf)?;
    Ok(())
}
