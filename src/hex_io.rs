///! Hex utilities for accepting any hex input from commandline ([`AnyHex`]) or any supported key
///! material ([`AnyKey`]). There's also the rendering utility of [`HexString`].
use codec::{Decode, Encode};
use std::fmt;
use std::str::FromStr;

#[derive(Encode, Decode)]
pub(crate) enum AnyPublicKey {
    Sr25519([u8; 32]),
    Bls([u8; 48]),
}

impl FromStr for AnyPublicKey {
    type Err = InvalidTaggedHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match AnyKey::from_str(s)? {
            AnyKey::Sr25519(x) => Self::Sr25519(x),
            AnyKey::BlsPublic(x) => Self::Bls(x),
            _ => return Err(InvalidTaggedHex::invalid_length()),
        })
    }
}

impl fmt::Debug for AnyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // as we are expected as public keys, go ahead and dump the input representation
        match self {
            AnyPublicKey::Sr25519(x) => write!(f, "sr25519:{:?}", HexString(x)),
            AnyPublicKey::Bls(x) => write!(f, "bls12:{:?}", HexString(x)),
        }
    }
}

impl AsRef<[u8]> for AnyPublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            AnyPublicKey::Sr25519(x) => x,
            AnyPublicKey::Bls(x) => x,
        }
    }
}

pub(crate) enum AnyPrivateKey {
    Sr25519([u8; 32]),
    Bls([u8; 32]),
}

impl FromStr for AnyPrivateKey {
    type Err = InvalidTaggedHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match AnyKey::from_str(s)? {
            AnyKey::Sr25519(x) => Self::Sr25519(x),
            AnyKey::BlsPrivate(x) => Self::Bls(x),
            _ => return Err(InvalidTaggedHex::invalid_length()),
        })
    }
}

impl fmt::Debug for AnyPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AnyPrivateKey::Sr25519(_) => "Sr25519",
            AnyPrivateKey::Bls(_) => "Bls",
        })
    }
}

impl AnyPrivateKey {
    #[cfg(test)]
    pub(crate) fn as_bls(&self) -> Option<&[u8; 32]> {
        match self {
            AnyPrivateKey::Bls(x) => Some(x),
            _ => None,
        }
    }
}

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
enum AnyKey {
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
                _ => return Err(InvalidTaggedHex::invalid_length()),
            },
            x => return Err(InvalidTaggedHex::InvalidPrefix(x.to_owned())),
        };

        Ok(key)
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

impl InvalidTaggedHex {
    fn invalid_length() -> Self {
        InvalidTaggedHex::InvalidHex(hex::FromHexError::InvalidStringLength)
    }
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

impl From<Vec<u8>> for AnyHex {
    fn from(x: Vec<u8>) -> Self {
        AnyHex(x)
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
