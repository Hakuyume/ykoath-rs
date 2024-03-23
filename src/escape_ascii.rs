use std::fmt::{self, Debug};

pub(crate) struct EscapeAscii<'a>(pub(crate) &'a [u8]);

impl Debug for EscapeAscii<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}
