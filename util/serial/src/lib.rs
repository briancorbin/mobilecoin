// Copyright (c) 2018-2022 The MobileCoin Foundation

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

pub extern crate prost;

pub use prost::{DecodeError, EncodeError, Message};
use serde::{Deserialize, Serialize};

// We put a new-type around serde_cbor::Error in `mod decode` and `mod encode`,
// because this keeps us compatible with how rmp-serde was exporting its errors,
// and avoids unnecessary code changes.
pub mod decode {
    #[derive(Debug)]
    pub struct Error(serde_cbor::Error);

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Cbor Decode Error: {}", self.0)
        }
    }

    impl From<serde_cbor::Error> for Error {
        fn from(src: serde_cbor::Error) -> Self {
            Self(src)
        }
    }
}

pub mod encode {
    #[derive(Debug)]
    pub struct Error(serde_cbor::Error);

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Cbor Encode Error: {}", self.0)
        }
    }

    impl From<serde_cbor::Error> for Error {
        fn from(src: serde_cbor::Error) -> Self {
            Self(src)
        }
    }
}

/// Serialize the given data structure.
///
/// Forward mc_util_serial::serialize to bincode::serialize(..., Infinite)
/// Serialization can fail if `T`'s implementation of `Serialize` decides to
/// fail.
pub fn serialize<T: ?Sized>(value: &T) -> Result<Vec<u8>, encode::Error>
where
    T: Serialize + Sized,
{
    Ok(serde_cbor::to_vec(value)?)
}

/// Deserialize the given bytes to a data structure.
///
/// Forward mc_util_serial::deserialize to serde_cbor::from_slice
pub fn deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, decode::Error>
where
    T: Deserialize<'a>,
{
    Ok(serde_cbor::from_slice(bytes)?)
}

pub fn encode<T: Message>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.encoded_len());
    value
        .encode(&mut buf)
        .expect("prost::encode with an unbounded buffer is no fail");
    buf
}

pub fn decode<T: Message>(buf: &[u8]) -> Result<T, DecodeError>
where
    T: core::default::Default,
{
    let value = T::decode(buf)?;
    Ok(value)
}

#[cfg(feature = "serde_with")]
mod json_u64 {

    use super::*;

    /// Represents u64 using string, when serializing to Json
    /// Javascript integers are not 64 bit, and so it is not really proper json.
    /// Using string avoids issues with some json parsers not handling large
    /// numbers well.
    ///
    /// This does not rely on the serde-json arbitrary precision feature, which
    /// (we fear) might break other things (e.g. https://github.com/serde-rs/json/issues/505)
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Hash, Serialize)]
    #[serde(transparent)]
    pub struct JsonU64(#[serde(with = "serde_with::rust::display_fromstr")] pub u64);

    impl From<&u64> for JsonU64 {
        fn from(src: &u64) -> Self {
            Self(*src)
        }
    }

    impl From<&JsonU64> for u64 {
        fn from(src: &JsonU64) -> u64 {
            src.0
        }
    }

    impl From<JsonU64> for u64 {
        fn from(src: JsonU64) -> u64 {
            src.0
        }
    }

    impl AsRef<u64> for JsonU64 {
        fn as_ref(&self) -> &u64 {
            &self.0
        }
    }
}

/// JsonU64 is exported if it is available -- the serde_with crate which it
/// depends on relies on std, so it must be optional.
#[cfg(feature = "serde_with")]
pub use json_u64::JsonU64;

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_serialize_string() {
        let the_string = "There goes the baker with his tray, like always";
        let serialized = serialize(&the_string).unwrap();
        let deserialized: &str = deserialize(&serialized).unwrap();
        assert_eq!(deserialized, the_string);
    }

    #[derive(PartialEq, Serialize, Deserialize, Debug)]
    struct TestStruct {
        vec: Vec<u8>,
        integer: u64,
        float: f64,
    }

    #[test]
    fn test_serialize_struct() {
        let the_struct = TestStruct {
            vec: vec![233, 123, 0, 12],
            integer: 4_242_424_242,
            float: 1.2345,
        };
        let serialized = serialize(&the_struct).unwrap();
        let deserialized: TestStruct = deserialize(&serialized).unwrap();
        assert_eq!(deserialized, the_struct);
    }
}

#[cfg(all(test, feature = "serde_with"))]
mod json_u64_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(PartialEq, Serialize, Deserialize, Debug)]
    struct TestStruct {
        nums: Vec<JsonU64>,
        block: JsonU64,
    }

    #[test]
    fn test_serialize_jsonu64_struct() {
        let the_struct = TestStruct {
            nums: (&[0, 1, 2, u64::MAX]).iter().map(Into::into).collect(),
            block: JsonU64(u64::MAX - 1),
        };
        let serialized = serialize(&the_struct).unwrap();
        let deserialized: TestStruct = deserialize(&serialized).unwrap();
        assert_eq!(deserialized, the_struct);
    }
}
