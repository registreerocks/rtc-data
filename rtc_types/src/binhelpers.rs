use core::mem::size_of;

use rkyv::{
    archived_root,
    ser::{
        serializers::{BufferSerializer, BufferSerializerError},
        Serializer,
    },
    validation::{
        check_archived_root_with_context,
        validators::{ArchiveBoundsError, ArchiveBoundsValidator},
    },
    Aligned, Archive, Deserialize, Infallible, Serialize, Unreachable,
};

pub fn rkyv_write_const<T>(
    value: &T,
) -> Result<[u8; size_of::<T::Archived>()], BufferSerializerError>
where
    T: Serialize<BufferSerializer<Aligned<[u8; size_of::<T::Archived>()]>>>,
{
    let mut serializer = BufferSerializer::new(Aligned([0u8; size_of::<T::Archived>()]));
    serializer.serialize_value(value)?;
    let buf = serializer.into_inner();
    Ok(buf.0)
}

/// # Safety
///
/// See [`archived_root`].
pub unsafe fn rkyv_read_const_archived<T>(bytes: &[u8; size_of::<T::Archived>()]) -> &T::Archived
where
    T: Archive,
{
    archived_root::<T>(bytes)
}

/// # Safety
///
/// See [`rkyv_read_const_archived`], [`archived_root`]
pub unsafe fn rkyv_read_const<T>(bytes: &[u8; size_of::<T::Archived>()]) -> T
where
    T: Archive,
    T::Archived: Deserialize<T, Infallible>,
{
    let archived = rkyv_read_const_archived::<T>(bytes);
    let result: Result<T, Unreachable> = archived.deserialize(&mut Infallible);
    // Safety: this should not allocate.
    result.expect("rkyv_read_const: unexpected deserialize failure!")
}

#[cfg(test)]
mod tests {
    use core::mem::{size_of, size_of_val};
    use rkyv::{Archive, Deserialize, Serialize};

    use super::*;

    /// Test struct from <https://github.com/djkoloski/rkyv#rkyv-in-action>
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    struct Test {
        int: i32,
        option: Option<i32>,
    }

    const TEST_SIZE: usize = size_of::<<Test as Archive>::Archived>();

    #[test]
    fn prop_roundtrip() -> Result<(), BufferSerializerError> {
        let t = Test {
            int: 5,
            option: Some(42),
        };
        let bytes = rkyv_write_const(&t)?;
        assert_eq!(size_of_val(&bytes), TEST_SIZE);

        let t_a = unsafe { rkyv_read_const_archived::<Test>(&bytes) };
        assert_eq!(t.int, t_a.int);
        assert_eq!(t.option, t_a.option);

        let t_2 = unsafe { rkyv_read_const(&bytes) };
        assert_eq!(t, t_2);

        Ok(())
    }
}

pub fn rkyv_read_archived<'a, T>(bytes: &[u8]) -> Result<&'a T::Archived, ArchiveBoundsError>
where
    T: Archive,
{
    let context = &mut ArchiveBoundsValidator { bytes };
    let archived = check_archived_root_with_context(bytes, context)?;
    Ok(archived)
}

// pub fn rkyv_read_deserialize() {}
