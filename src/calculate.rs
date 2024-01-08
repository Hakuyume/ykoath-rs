use crate::{Error, YubiKey};

#[derive(Debug)]
pub struct Response<'a> {
    pub digits: u8,
    pub response: &'a [u8],
}

impl Response<'_> {
    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L240
    pub fn code(&self) -> String {
        let mut response = 0_u32.to_be_bytes();
        let len = response.len();
        response[len.saturating_sub(self.response.len())..]
            .copy_from_slice(&self.response[self.response.len().saturating_sub(len)..]);
        format!(
            "{:01$}",
            (u32::from_be_bytes(response) & 0x7fff_ffff) % 10_u32.pow(u32::from(self.digits)),
            usize::from(self.digits),
        )
    }
}

impl YubiKey {
    #[tracing::instrument(err, fields(name = name.escape_ascii().to_string()), ret, skip(name, buf))]
    pub fn calculate<'a>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<Response<'a>, Error> {
        let buf = buf; // https://github.com/tokio-rs/tracing/issues/2796
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
