use crate::escape_ascii::EscapeAscii;
use crate::{Error, YubiKey};
use std::fmt::{self, Display};

#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    pub digits: u8,
    pub response: &'a [u8],
}

impl Response<'_> {
    pub fn code(&self) -> Code {
        let mut response = 0_u32.to_be_bytes();
        let len = response.len();
        response[len.saturating_sub(self.response.len())..]
            .copy_from_slice(&self.response[self.response.len().saturating_sub(len)..]);
        Code {
            digits: self.digits,
            response: u32::from_be_bytes(response),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Code {
    digits: u8,
    response: u32,
}

impl Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L240
        write!(
            f,
            "{:01$}",
            (self.response & 0x7fff_ffff) % 10_u32.pow(u32::from(self.digits)),
            usize::from(self.digits),
        )
    }
}

impl YubiKey {
    #[tracing::instrument(err, fields(name = ?EscapeAscii(name)), ret, skip(name, buf))]
    pub fn calculate<'a>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<Response<'a>, Error> {
        // https://github.com/tokio-rs/tracing/issues/2796
        #[allow(clippy::redundant_locals)]
        let buf = buf;
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa2, 0x00, if truncate { 0x01 } else { 0x00 }]);
        buf.push(0x00);
        Self::push(buf, 0x71, name);
        Self::push(buf, 0x74, challenge);
        let mut response = self.transmit(buf)?;
        let (_, response) = Self::pop(&mut response, &[if truncate { 0x76 } else { 0x75 }])?;
        Ok(Response {
            digits: *response.first().ok_or(Error::InsufficientData)?,
            response: &response[1..],
        })
    }
}
