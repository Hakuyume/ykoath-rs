use crate::{Error, YubiKey};
use std::fmt;
use std::iter;

pub struct Response<'a> {
    pub name: &'a [u8],
    pub inner: Inner<'a>,
}

impl fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("name", &self.name.escape_ascii().to_string())
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Debug)]
pub enum Inner<'a> {
    Response(crate::calculate::Response<'a>),
    Hotp,
    Touch,
}

impl YubiKey {
    #[tracing::instrument(err, ret, skip(buf))]
    pub fn calculate_all<'a>(
        &self,
        truncate: bool,
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<Vec<Response<'a>>, Error> {
        let buf = buf; // https://github.com/tokio-rs/tracing/issues/2796
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa4, 0x00, if truncate { 0x01 } else { 0x00 }]);
        buf.push(0x00);
        Self::push(buf, 0x74, challenge);
        let mut response = self.transmit(buf)?;
        iter::from_fn(|| {
            if response.is_empty() {
                None
            } else {
                Some(Self::pop(&mut response, &[0x71]).and_then(|(_, name)| {
                    let (tag, response) = Self::pop(
                        &mut response,
                        &[if truncate { 0x76 } else { 0x75 }, 0x77, 0x7c],
                    )?;
                    let inner = match tag {
                        0x75 | 0x76 => {
                            let digits = *response.first().ok_or(Error::InsufficientData)?;
                            let response = &response[1..];
                            Ok(Inner::Response(crate::calculate::Response {
                                digits,
                                response,
                            }))
                        }
                        0x77 => Ok(Inner::Hotp),
                        0x7c => Ok(Inner::Touch),
                        _ => Err(Error::UnexpectedValue(tag)),
                    }?;
                    Ok(Response { name, inner })
                }))
            }
        })
        .collect()
    }
}
