///! Hex utilities for accepting any hex input from commandline ([`AnyHex`]) or any supported key
///! material ([`AnyKey`]). There's also the rendering utility of [`HexString`].
use codec::{Decode, Encode};
use std::fmt;
use std::str::FromStr;

/// Lower level enumeration of supported keys for reading them from the command line for easy
/// access. Later more secure ways to obtain the material can be implemented.
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

impl AnyKey {
    /// Returns the key material as a slice.
    ///
    /// # Safety
    ///
    /// There are no preconditions to uphold however this should not be used by mistake in any of
    /// the (de)serialization code as it will be very easy to mix up different key types, leading
    /// to subtle bugs.
    pub(crate) unsafe fn as_slice(&self) -> &[u8] {
        match self {
            AnyKey::Sr25519(x) => x,
            AnyKey::BlsPublic(x) => x,
            AnyKey::BlsPrivate(x) => x,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_sr25519(&self) -> Option<&[u8; 32]> {
        match self {
            AnyKey::Sr25519(x) => Some(x),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_bls_private(&self) -> Option<&[u8; 32]> {
        match self {
            AnyKey::BlsPrivate(x) => Some(x),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_bls_public(&self) -> Option<&[u8; 48]> {
        match self {
            AnyKey::BlsPublic(x) => Some(x),
            _ => None,
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
