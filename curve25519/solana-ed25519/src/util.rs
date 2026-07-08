use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serializer};

pub(crate) fn serialize_bytes_32<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut tup = serializer.serialize_tuple(32)?;
    for byte in bytes.iter() {
        tup.serialize_element(byte)?;
    }
    tup.end()
}

pub(crate) fn deserialize_bytes_32<'de, D>(
    deserializer: D,
    expected: &'static str,
) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    struct Bytes32Visitor {
        expected: &'static str,
    }

    impl<'de> Visitor<'de> for Bytes32Visitor {
        type Value = [u8; 32];

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str(self.expected)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<[u8; 32], A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut bytes = [0u8; 32];
            #[allow(clippy::needless_range_loop)]
            for i in 0..32 {
                bytes[i] = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(i, &"expected 32 bytes"))?;
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_tuple(32, Bytes32Visitor { expected })
}
