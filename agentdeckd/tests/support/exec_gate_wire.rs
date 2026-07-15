//! Integration harness codec for the private exec-gate wire.
//!
//! Production owns the decoder; this independent encoder/decoder prevents the live binary test
//! from passing merely because it calls the same implementation on both ends.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

pub const GATE_PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME_BYTES: usize = 512 * 1024;
const MAGIC: [u8; 4] = *b"ADGX";
const CODEC_VERSION: u16 = 1;
const PREPARE_TAG: u8 = 1;
const RELEASE_TAG: u8 = 2;
const READY_TAG: u8 = 3;
const ABORTED_TAG: u8 = 4;
const MAX_NONCE_BYTES: usize = 1024;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
const TOKEN_BYTES: usize = 32;
const MAX_ERROR_CODE_BYTES: usize = 128;

#[derive(Clone, Debug)]
pub enum ParentFrame {
    Prepare {
        protocol_version: u16,
        command_id: String,
        daemon_boot_id: String,
        execution_nonce: Vec<u8>,
        program: Vec<u8>,
        arguments: Vec<Vec<u8>>,
        cwd: Vec<u8>,
    },
    Release {
        command_id: String,
        daemon_boot_id: String,
        execution_nonce: Vec<u8>,
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
        release_token: Vec<u8>,
        token_commitment: Vec<u8>,
        release_authorized_at_ms: u64,
    },
}

#[derive(Clone, Debug)]
pub enum ChildFrame {
    Ready {
        protocol_version: u16,
        process_group_id: i64,
        leader_pid: i64,
        leader_start_time: u64,
        execution_nonce: Vec<u8>,
        release_token: Vec<u8>,
        token_commitment: Vec<u8>,
    },
    Aborted {
        code: String,
    },
}

pub fn write_frame(stream: &mut UnixStream, frame: &ParentFrame) -> io::Result<()> {
    let mut encoder = Encoder::new(match frame {
        ParentFrame::Prepare { .. } => PREPARE_TAG,
        ParentFrame::Release { .. } => RELEASE_TAG,
    });
    match frame {
        ParentFrame::Prepare {
            protocol_version,
            command_id,
            daemon_boot_id,
            execution_nonce,
            program,
            arguments,
            cwd,
        } => {
            if arguments.len() > MAX_ARGUMENTS {
                return Err(invalid("too many gate arguments"));
            }
            encoder.u16(*protocol_version);
            encoder.bytes(command_id.as_bytes(), 36)?;
            encoder.bytes(daemon_boot_id.as_bytes(), 36)?;
            encoder.bytes(execution_nonce, MAX_NONCE_BYTES)?;
            encoder.bytes(program, MAX_PATH_BYTES)?;
            encoder.u16(
                u16::try_from(arguments.len()).map_err(|_| invalid("argument count overflow"))?,
            );
            for argument in arguments {
                encoder.bytes(argument, MAX_ARGUMENT_BYTES)?;
            }
            encoder.bytes(cwd, MAX_PATH_BYTES)?;
        }
        ParentFrame::Release {
            command_id,
            daemon_boot_id,
            execution_nonce,
            process_group_id,
            leader_pid,
            leader_start_time,
            release_token,
            token_commitment,
            release_authorized_at_ms,
        } => {
            encoder.bytes(command_id.as_bytes(), 36)?;
            encoder.bytes(daemon_boot_id.as_bytes(), 36)?;
            encoder.bytes(execution_nonce, MAX_NONCE_BYTES)?;
            encoder.i64(*process_group_id);
            encoder.i64(*leader_pid);
            encoder.u64(*leader_start_time);
            encoder.exact(release_token, TOKEN_BYTES)?;
            encoder.exact(token_commitment, TOKEN_BYTES)?;
            encoder.u64(*release_authorized_at_ms);
        }
    }
    let payload = encoder.finish()?;
    let length = u32::try_from(payload.len()).map_err(|_| invalid("frame length overflow"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

pub fn read_frame(stream: &mut UnixStream) -> io::Result<ChildFrame> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| invalid("invalid gate frame length"))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid("gate frame exceeds fixed bound"));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    let mut decoder = Decoder::new(&payload)?;
    let frame = match decoder.tag {
        READY_TAG => ChildFrame::Ready {
            protocol_version: decoder.u16()?,
            process_group_id: decoder.i64()?,
            leader_pid: decoder.i64()?,
            leader_start_time: decoder.u64()?,
            execution_nonce: decoder.bytes(MAX_NONCE_BYTES)?,
            release_token: decoder.exact(TOKEN_BYTES)?,
            token_commitment: decoder.exact(TOKEN_BYTES)?,
        },
        ABORTED_TAG => ChildFrame::Aborted {
            code: String::from_utf8(decoder.bytes(MAX_ERROR_CODE_BYTES)?)
                .map_err(|_| invalid("gate error code is not UTF-8"))?,
        },
        _ => return Err(invalid("unexpected gate reply tag")),
    };
    decoder.finish()?;
    Ok(frame)
}

struct Encoder {
    payload: Vec<u8>,
}

impl Encoder {
    fn new(tag: u8) -> Self {
        let mut payload = Vec::with_capacity(256);
        payload.extend_from_slice(&MAGIC);
        payload.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        payload.push(tag);
        Self { payload }
    }

    fn u16(&mut self, value: u16) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.payload.extend_from_slice(&value.to_be_bytes());
    }

    fn exact(&mut self, value: &[u8], expected: usize) -> io::Result<()> {
        if value.len() != expected {
            return Err(invalid("gate exact field length mismatch"));
        }
        self.bytes(value, expected)
    }

    fn bytes(&mut self, value: &[u8], max: usize) -> io::Result<()> {
        if value.len() > max {
            return Err(invalid("gate field exceeds fixed bound"));
        }
        self.u32(u32::try_from(value.len()).map_err(|_| invalid("field length overflow"))?);
        self.payload.extend_from_slice(value);
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(invalid("gate frame exceeds fixed bound"));
        }
        Ok(())
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME_BYTES {
            Err(invalid("gate frame exceeds fixed bound"))
        } else {
            Ok(self.payload)
        }
    }
}

struct Decoder<'a> {
    payload: &'a [u8],
    cursor: usize,
    tag: u8,
}

impl<'a> Decoder<'a> {
    fn new(payload: &'a [u8]) -> io::Result<Self> {
        if payload.len() < MAGIC.len() + 3 || payload.len() > MAX_FRAME_BYTES {
            return Err(invalid("invalid gate reply header"));
        }
        if payload[..MAGIC.len()] != MAGIC {
            return Err(invalid("invalid gate reply magic"));
        }
        let version = u16::from_be_bytes([payload[4], payload[5]]);
        if version != CODEC_VERSION {
            return Err(invalid("invalid gate reply codec version"));
        }
        Ok(Self {
            payload,
            cursor: MAGIC.len() + 3,
            tag: payload[MAGIC.len() + 2],
        })
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| invalid("invalid u16 field"))?,
        ))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| invalid("invalid u32 field"))?,
        ))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| invalid("invalid u64 field"))?,
        ))
    }

    fn i64(&mut self) -> io::Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| invalid("invalid i64 field"))?,
        ))
    }

    fn exact(&mut self, expected: usize) -> io::Result<Vec<u8>> {
        let value = self.bytes(expected)?;
        if value.len() == expected {
            Ok(value)
        } else {
            Err(invalid("gate exact field length mismatch"))
        }
    }

    fn bytes(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let length = usize::try_from(self.u32()?).map_err(|_| invalid("field length overflow"))?;
        if length > max {
            return Err(invalid("gate field exceeds fixed bound"));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| invalid("gate field offset overflow"))?;
        let value = self
            .payload
            .get(self.cursor..end)
            .ok_or_else(|| invalid("truncated gate reply"))?;
        self.cursor = end;
        Ok(value)
    }

    fn finish(self) -> io::Result<()> {
        if self.cursor == self.payload.len() {
            Ok(())
        } else {
            Err(invalid("trailing gate reply bytes"))
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
