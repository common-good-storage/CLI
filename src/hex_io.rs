///! Hex utilities for accepting any hex input from commandline ([`AnyHex`]) or any supported key
///! material ([`AnyKey`]). There's also the rendering utility of [`HexString`].
use codec::{Decode, Encode};
use std::fmt;
use std::str::FromStr;

/// Enumeration of supported keys, currently just sr25519.
///
/// The string input format is:
///
/// ```
/// tag + ":" + hex
/// ```
///
/// Where tag is any of the variants in lowercase, hex is the variant specific length hex string.
#[derive(Encode, Decode)]
pub(crate) enum AnyKey {
    Sr25519([u8; 32]),
    BlsPrivate([u8; 32]),
    BlsPublic([u8; 48]),
}

impl FromStr for AnyKey {
    type Err = InvalidTaggedHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let pos = s
            .bytes()
            .position(|ch| ch == b':')
            .ok_or(InvalidTaggedHex::MissingSeparator)?;

        let (prefix, hex) = (&s[..pos], &s[(pos + 1)..]);

        let key = match prefix {
            "sr25519" => AnyKey::Sr25519(<[u8; 32]>::from_hex(hex)?),
            "bls12" => match hex.len() {
                64 => AnyKey::BlsPrivate(<[u8; 32]>::from_hex(hex)?),
                96 => AnyKey::BlsPublic(<[u8; 48]>::from_hex(hex)?),
                _ => {
                    return Err(InvalidTaggedHex::InvalidHex(
                        hex::FromHexError::InvalidStringLength,
                    ))
                }
            },
            x => return Err(InvalidTaggedHex::InvalidPrefix(x.to_owned())),
        };

        Ok(key)
    }
}

impl AsRef<[u8]> for AnyKey {
    fn as_ref(&self) -> &[u8] {
        // this method is ... not great if the input was a minisecretkey, but then again, we are
        // reading all of them on the command line at the moment.
        match self {
            AnyKey::Sr25519(x) => x,
            AnyKey::BlsPublic(x) => x,
            AnyKey::BlsPrivate(x) => x,
        }
    }
}

impl fmt::Debug for AnyKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // don't output the key in case it was a private key, just in principle.
            AnyKey::Sr25519(_) => write!(fmt, "Sr25519"),
            AnyKey::BlsPublic(_) | AnyKey::BlsPrivate(_) => write!(fmt, "Bls12"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum InvalidTaggedHex {
    MissingSeparator,
    InvalidPrefix(String),
    InvalidHex(hex::FromHexError),
}

impl From<hex::FromHexError> for InvalidTaggedHex {
    fn from(e: hex::FromHexError) -> Self {
        InvalidTaggedHex::InvalidHex(e)
    }
}

impl fmt::Display for InvalidTaggedHex {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InvalidTaggedHex::*;
        match self {
            MissingSeparator => write!(fmt, "value is missing the type:hex separator ':'"),
            InvalidPrefix(p) => write!(fmt, "unsupported type: {:?}", p),
            InvalidHex(e) => write!(fmt, "invalid hex: {}", e),
        }
    }
}

#[derive(Encode, Decode)]
pub(crate) struct AnyHex(pub Vec<u8>);

impl AsRef<[u8]> for AnyHex {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl FromStr for AnyHex {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        Ok(AnyHex(Vec::from_hex(s)?))
    }
}

impl fmt::Debug for AnyHex {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "AnyHex({:?})", HexString(&self.0))
    }
}

/// Simple utility for rendering a slice as hex.
// Separating this from AnyHex in order to handle the key material the same way.
pub(crate) struct HexString<'a>(pub &'a [u8]);

impl fmt::Debug for HexString<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(fmt, "{:02x}", b)?
        }
        Ok(())
    }
}
