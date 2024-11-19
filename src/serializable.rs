/// Takes an integer type, and it's size in bytes and implements Serializable for that type
macro_rules! impl_serializable {
    ($t:ty) => {
        impl Serializable for $t {
            type Bytes = [u8; std::mem::size_of::<$t>()];
            fn to_le_bytes(&self) -> Self::Bytes {
                <$t>::to_le_bytes(*self)
            }
        }
    };
}

/// Trait for numeric types that can be serialized to a sequence of bytes
/// We need this because there's no trait to determine which types implement
/// .to_le_bytes() or similar, even though all integer types do that already.
/// With this trait we can call .to_le_bytes() in all integers specified in the macros in order to hash them.
pub trait Serializable {
    type Bytes: AsRef<[u8]>;
    fn to_le_bytes(&self) -> Self::Bytes;
}

impl_serializable!(u8);
impl_serializable!(u16);
impl_serializable!(u32);
impl_serializable!(u64);
impl_serializable!(u128);

impl_serializable!(i8);
impl_serializable!(i16);
impl_serializable!(i32);
impl_serializable!(i64);
impl_serializable!(i128);
