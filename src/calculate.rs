use crate::{Error, YubiKey};

#[derive(Debug)]
pub struct Response<'a> {
    pub digits: u8,
    pub response: &'a [u8],
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
