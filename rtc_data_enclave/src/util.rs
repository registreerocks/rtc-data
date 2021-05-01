pub fn concat_u8<const A: usize, const B: usize>(a: &[u8; A], b: &[u8; B]) -> [u8; A + B] {
    let mut whole: [u8; A + B] = [Default::default(); A + B];
    let (one, two) = whole.split_at_mut(A);
    one.copy_from_slice(a);
    two.copy_from_slice(b);
    whole
}
