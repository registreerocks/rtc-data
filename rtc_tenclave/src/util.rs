pub fn concat_u8<const A: usize, const B: usize>(a: &[u8; A], b: &[u8; B]) -> [u8; A + B] {
    let mut whole: [u8; A + B] = [Default::default(); A + B];
    let (one, two) = whole.split_at_mut(A);
    one.copy_from_slice(a);
    two.copy_from_slice(b);
    whole
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concat_u8_works() {
        const ARR1_SIZE: usize = 43;
        const ARR2_SIZE: usize = 43;

        let arr1 = [87_u8; ARR1_SIZE];
        let arr2 = [34_u8; ARR2_SIZE];

        let merged = concat_u8(&arr1, &arr2);

        let (split1, split2) = merged.split_at(ARR1_SIZE);

        assert_eq!(split1, arr1);
        assert_eq!(split2, arr2);
    }
}
