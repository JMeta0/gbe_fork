use std::fmt;

pub const MAGIC: u32 = 0x4C524247;
pub const VERSION: u16 = 1;

pub const MSG_HELLO: u16 = 1;
pub const MSG_REGISTER: u16 = 2;
pub const MSG_WELCOME: u16 = 3;
pub const MSG_HEARTBEAT: u16 = 4;
pub const MSG_RELIABLE: u16 = 5;
pub const MSG_UNRELIABLE: u16 = 6;
pub const MSG_DISCONNECT: u16 = 7;

pub const FLAG_BROADCAST: u32 = 1 << 0;
pub const FLAG_HAS_DEST_STEAM_ID: u32 = 1 << 1;
pub const FLAG_HAS_DEST_ENDPOINT: u32 = 1 << 2;

const HEADER_SIZE: usize = 52;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub msg_type: u16,
    pub flags: u32,
    pub app_id: u32,
    pub source_id: u64,
    pub dest_id: u64,
    pub source_virtual_ip: u32,
    pub source_virtual_port: u16,
    pub dest_virtual_ip: u32,
    pub dest_virtual_port: u16,
    pub session_token: u64,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn heartbeat(app_id: u32) -> Self {
        Self {
            msg_type: MSG_HEARTBEAT,
            flags: 0,
            app_id,
            source_id: 0,
            dest_id: 0,
            source_virtual_ip: 0,
            source_virtual_port: 0,
            dest_virtual_ip: 0,
            dest_virtual_port: 0,
            session_token: 0,
            payload: Vec::new(),
        }
    }
}

pub fn encode_envelope(env: &Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + env.payload.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&env.msg_type.to_le_bytes());
    out.extend_from_slice(&env.flags.to_le_bytes());
    out.extend_from_slice(&env.app_id.to_le_bytes());
    out.extend_from_slice(&env.source_id.to_le_bytes());
    out.extend_from_slice(&env.dest_id.to_le_bytes());
    out.extend_from_slice(&env.source_virtual_ip.to_le_bytes());
    out.extend_from_slice(&env.source_virtual_port.to_le_bytes());
    out.extend_from_slice(&env.dest_virtual_ip.to_le_bytes());
    out.extend_from_slice(&env.dest_virtual_port.to_le_bytes());
    out.extend_from_slice(&env.session_token.to_le_bytes());
    out.extend_from_slice(&(env.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&env.payload);
    out
}

pub fn decode_envelope(data: &[u8]) -> Result<Envelope, ProtocolError> {
    if data.len() < HEADER_SIZE {
        return Err(ProtocolError("frame too short"));
    }

    let mut off = 0usize;
    let magic = read_u32(data, &mut off)?;
    if magic != MAGIC {
        return Err(ProtocolError("invalid magic"));
    }
    let version = read_u16(data, &mut off)?;
    if version != VERSION {
        return Err(ProtocolError("unsupported version"));
    }

    let msg_type = read_u16(data, &mut off)?;
    let flags = read_u32(data, &mut off)?;
    let app_id = read_u32(data, &mut off)?;
    let source_id = read_u64(data, &mut off)?;
    let dest_id = read_u64(data, &mut off)?;
    let source_virtual_ip = read_u32(data, &mut off)?;
    let source_virtual_port = read_u16(data, &mut off)?;
    let dest_virtual_ip = read_u32(data, &mut off)?;
    let dest_virtual_port = read_u16(data, &mut off)?;
    let session_token = read_u64(data, &mut off)?;
    let payload_len = read_u32(data, &mut off)? as usize;
    if off + payload_len != data.len() {
        return Err(ProtocolError("invalid payload length"));
    }

    Ok(Envelope {
        msg_type,
        flags,
        app_id,
        source_id,
        dest_id,
        source_virtual_ip,
        source_virtual_port,
        dest_virtual_ip,
        dest_virtual_port,
        session_token,
        payload: data[off..].to_vec(),
    })
}

pub fn frame_tcp(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn next_tcp_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }
    let size = u32::from_le_bytes(buffer[0..4].try_into().ok()?) as usize;
    if buffer.len() < 4 + size {
        return None;
    }
    let frame = buffer[4..4 + size].to_vec();
    buffer.drain(0..4 + size);
    Some(frame)
}

pub fn encode_ids_payload(listen_port: u16, ids: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ids.len() * 8);
    out.extend_from_slice(&listen_port.to_le_bytes());
    out.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

pub fn decode_ids_payload(payload: &[u8]) -> Result<(u16, Vec<u64>), ProtocolError> {
    if payload.len() < 4 {
        return Err(ProtocolError("payload too short"));
    }
    let listen_port = u16::from_le_bytes(payload[0..2].try_into().unwrap());
    let count = u16::from_le_bytes(payload[2..4].try_into().unwrap()) as usize;
    if payload.len() != 4 + count * 8 {
        return Err(ProtocolError("payload length mismatch"));
    }
    let mut ids = Vec::with_capacity(count);
    let mut off = 4usize;
    while off < payload.len() {
        ids.push(u64::from_le_bytes(payload[off..off + 8].try_into().unwrap()));
        off += 8;
    }
    Ok((listen_port, ids))
}

#[derive(Debug, Clone, Copy)]
pub struct ProtocolError(pub &'static str);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ProtocolError {}

fn read_u16(data: &[u8], off: &mut usize) -> Result<u16, ProtocolError> {
    if *off + 2 > data.len() {
        return Err(ProtocolError("frame too short"));
    }
    let value = u16::from_le_bytes(data[*off..*off + 2].try_into().unwrap());
    *off += 2;
    Ok(value)
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, ProtocolError> {
    if *off + 4 > data.len() {
        return Err(ProtocolError("frame too short"));
    }
    let value = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(value)
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64, ProtocolError> {
    if *off + 8 > data.len() {
        return Err(ProtocolError("frame too short"));
    }
    let value = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(value)
}
