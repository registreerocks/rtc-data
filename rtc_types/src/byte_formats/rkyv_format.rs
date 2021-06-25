//! [`rkyv`] byte format helpers.

use core::mem::size_of;

use rkyv::ser::serializers::{BufferSerializer, BufferSerializerError};
use rkyv::ser::Serializer;
use rkyv::{archived_root, Aligned, Archive, Deserialize, Infallible, Serialize, Unreachable};

pub fn write_array<T>(value: &T) -> Result<[u8; size_of::<T::Archived>()], BufferSerializerError>
where
    T: Serialize<BufferSerializer<Aligned<[u8; size_of::<T::Archived>()]>>>,
{
    let mut serializer = BufferSerializer::new(Aligned([0u8; size_of::<T::Archived>()]));
    serializer.serialize_value(value)?;
    let Aligned(buf) = serializer.into_inner();
    Ok(buf)
}

/// # Safety
///
/// This does not perform input validation, and may have undefined behaviour for untrusted input.
///
/// See safety of [`archived_root`]:
///
/// > The caller must guarantee that the byte slice represents an archived object and that the root
/// > object is stored at the end of the byte slice.
///
/// TODO: Use `check_archived_root` once it's stable without `std` (rkyv 0.7.0?).
///       See issue: [no_std validation #107](https://github.com/djkoloski/rkyv/issues/107)
pub unsafe fn view_array<T>(bytes: &[u8; size_of::<T::Archived>()]) -> &T::Archived
where
    T: Archive,
{
    archived_root::<T>(bytes)
}

/// # Safety
///
/// See safety of [`view_array`].
pub unsafe fn read_array<T>(bytes: &[u8; size_of::<T::Archived>()]) -> T
where
    T: Archive,
    T::Archived: Deserialize<T, Infallible>,
{
    let archived = view_array::<T>(bytes);
    let result: Result<T, Unreachable> = archived.deserialize(&mut Infallible);
    // Safety: this should not allocate, so it should not fail.
    result.expect("read_array: unexpected deserialize failure!")
}

#[cfg(test)]
mod tests {
    use core::mem::{size_of, size_of_val};

    use proptest::prelude::*;
    use proptest_derive::Arbitrary;
    use rkyv::{Archive, Deserialize, Serialize};

    use super::*;

    /// Arbitrary structure to test with.
    #[derive(
        Debug,
        PartialEq,
        // rkyv:
        Archive,
        Deserialize,
        Serialize,
        // proptest:
        Arbitrary,
    )]
    struct Foo {
        byte: u8,
        int: u32,
        opt: Option<i32>,
        ary: [u8; 16],
    }

    const ARCHIVED_FOO_SIZE: usize = size_of::<ArchivedFoo>();

    /// [`write_array`] roundtrips with [`view_array`] and [`read_array`].
    #[test]
    fn prop_rkyv_array_roundtrip() {
        let test = |value: &Foo| {
            let bytes = &write_array(value).unwrap();
            assert_eq!(size_of_val(bytes), ARCHIVED_FOO_SIZE);

            let view = unsafe { view_array::<Foo>(bytes) };
            assert_eq!(value.byte, view.byte);
            assert_eq!(value.int, view.int);
            assert_eq!(value.opt, view.opt);
            assert_eq!(value.ary, view.ary);

            let read = &unsafe { read_array(bytes) };
            assert_eq!(value, read);
        };
        proptest!(|(value: Foo)| test(&value));
    }
}
