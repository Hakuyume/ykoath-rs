use crate::escape_ascii::EscapeAscii;
use crate::{Algorithm, Error, Type, YubiKey};
use std::fmt::{self, Debug};
use std::iter;

#[derive(Clone, Copy)]
pub struct Response<'a> {
    pub type_: Type,
    pub algorithm: Algorithm,
    pub name: &'a [u8],
}

impl Debug for Response<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("type_", &self.type_)
            .field("algorithm", &self.algorithm)
            .field("name", &EscapeAscii(self.name))
            .finish()
    }
}

impl YubiKey {
    #[tracing::instrument(err, ret, skip(buf))]
    pub fn list<'a>(&self, buf: &'a mut Vec<u8>) -> Result<Vec<Response<'a>>, Error> {
        // https://github.com/tokio-rs/tracing/issues/2796
        #[allow(clippy::redundant_locals)]
        let buf = buf;
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa1, 0x00, 0x00]);
        buf.push(0x00);
        let mut response = self.transmit(buf)?;
        iter::from_fn(|| {
            if response.is_empty() {
                None
            } else {
                Some(Self::pop(&mut response, &[0x72]).and_then(|(_, data)| {
                    let type_algorithm = data.first().ok_or(Error::InsufficientData)?;
                    let name = data.get(1..).ok_or(Error::InsufficientData)?;
                    let type_ = Type::try_from(*type_algorithm & 0xf0)?;
                    let algorithm = Algorithm::try_from(*type_algorithm & 0x0f)?;
                    Ok(Response {
                        type_,
                        algorithm,
                        name,
                    })
                }))
            }
        })
        .collect()
    }
}
