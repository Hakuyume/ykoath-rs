use std::num::TryFromIntError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pcsc(#[from] pcsc::Error),
    #[error(transparent)]
    TryFromInt(#[from] TryFromIntError),

    #[error("no YubiKey found")]
    NoDevice,
    #[error("response does not have enough length")]
    InsufficientData,
    #[error("unknown response code (0x{0:04x})")]
    UnknownCode(u16),
    #[error("unexpected value (0x{0:02x}")]
    UnexpectedValue(u8),
    #[error("no space")]
    NoSpace,
    #[error("no such object")]
    NoSuchObject,
    #[error("auth required")]
    AuthRequired,
    #[error("wrong syntax")]
    WrongSyntax,
    #[error("generic error")]
    GenericError,
}
