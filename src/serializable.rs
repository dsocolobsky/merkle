/// Takes an integer type and it's size in bytes and implements Serializable for that type
macro_rules! impl_serializable {
    ($t:ty, $size:expr) => {
        impl Serializable for $t {
            type Bytes = [u8; $size];
            fn to_le_bytes(&self) -> Self::Bytes {
                <$t>::to_le_bytes(*self)
            }
        }
    };
}

/// Trait for numeric types that can be serialized to a sequence of bytes
pub trait Serializable {
    type Bytes: AsRef<[u8]>;
    fn to_le_bytes(&self) -> Self::Bytes;
}

impl_serializable!(u8, 1);
impl_serializable!(u16, 2);
impl_serializable!(u32, 4);
impl_serializable!(u64, 8);
impl_serializable!(u128, 16);

impl_serializable!(i8, 1);
impl_serializable!(i16, 2);
impl_serializable!(i32, 4);
impl_serializable!(i64, 8);
impl_serializable!(i128, 16);
