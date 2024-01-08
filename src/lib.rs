//! https://developers.yubico.com/OATH/YKOATH_Protocol.html

pub mod calculate;
pub mod calculate_all;
mod error;
pub mod select;

pub use error::Error;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use std::ffi::CString;
use std::fmt;

pub struct YubiKey {
    name: CString,
    card: Card,
}

impl fmt::Debug for YubiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("YubiKey").field(&self.name).finish()
    }
}

impl YubiKey {
    #[tracing::instrument(err, ret, skip_all)]
    pub fn connect(buf: &mut Vec<u8>) -> Result<Self, Error> {
        let context = Context::establish(Scope::User)?;
        Self::connect_with(&context, buf)
    }

    #[tracing::instrument(err, ret, skip_all)]
    pub fn connect_with(context: &Context, buf: &mut Vec<u8>) -> Result<Self, Error> {
        // https://github.com/Yubico/yubikey-manager/blob/4.0.9/ykman/pcsc/__init__.py#L46
        const NAME: &[u8] = b"yubico yubikey";

        buf.resize(context.list_readers_len()?, 0);
        let name = context
            .list_readers(buf)?
            .find(|name| {
                // https://github.com/Yubico/yubikey-manager/blob/4.0.9/ykman/pcsc/__init__.py#L165
                name.to_bytes()
                    .to_ascii_lowercase()
                    .windows(NAME.len())
                    .any(|window| window == NAME)
            })
            .ok_or(Error::NoDevice)?;
        tracing::debug!(?name);
        Ok(Self {
            name: name.to_owned(),
            card: context.connect(name, ShareMode::Shared, Protocols::ANY)?,
        })
    }

    #[tracing::instrument(err, ret, skip(buf))]
    fn transmit<'a>(&self, buf: &'a mut Vec<u8>) -> Result<&'a [u8], Error> {
        let buf = buf;
        if buf.len() >= 5 {
            // Lc
            buf[4] = (buf.len() - 5) as _;
        }
        let mid = buf.len();
        loop {
            let len = buf.len();
            buf.resize(len + MAX_BUFFER_SIZE, 0);
            let (occupied, vacant) = buf.split_at_mut(len);
            let send = if mid == len {
                &occupied[..mid]
            } else {
                // SEND REMAINING INSTRUCTION
                &[0x00, 0xa5, 0x00, 0x00]
            };
            tracing::debug!(?send);
            let receive = self.card.transmit(send, vacant)?;
            tracing::debug!(?receive);
            let len = len + receive.len();
            buf.truncate(len);
            let code = u16::from_le_bytes([
                buf.pop().ok_or(Error::InsufficientData)?,
                buf.pop().ok_or(Error::InsufficientData)?,
            ]);
            match code {
                0x9000 => {
                    break Ok(&buf[mid..]);
                }
                0x6100..=0x61ff => Ok(()),
                0x6a84 => Err(Error::NoSpace),
                0x6984 => Err(Error::NoSuchObject),
                0x6982 => Err(Error::AuthRequired),
                0x6a80 => Err(Error::WrongSyntax),
                0x6581 => Err(Error::GenericError),
                _ => Err(Error::UnknownCode(code)),
            }?
        }
    }

    fn push(buf: &mut Vec<u8>, tag: u8, data: &[u8]) {
        buf.push(tag);
        buf.push(data.len() as _);
        buf.extend_from_slice(data);
    }

    fn pop<'a>(buf: &mut &'a [u8], tags: &[u8]) -> Result<(u8, &'a [u8]), Error> {
        let tag = *buf.first().ok_or(Error::InsufficientData)?;
        if tags.contains(&tag) {
            let len = *buf.get(1).ok_or(Error::InsufficientData)? as usize;
            let data = buf.get(2..2 + len).ok_or(Error::InsufficientData)?;
            *buf = &buf[2 + len..];
            Ok((tag, data))
        } else {
            Err(Error::UnexpectedValue(tag))
        }
    }
}

#[derive(Debug)]
pub enum Algorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}
