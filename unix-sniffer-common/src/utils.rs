use core::ops::Rem;

pub fn cap_size<T: Copy + PartialOrd + Rem<Output = T>>(size: T, cap: T) -> T {
    let mut ret = size;
    #[cfg(target_arch = "bpf")]
    {
        if size >= cap {
            return cap;
        }
        ret = size % cap;
    }
    ret
}

#[inline(always)]
#[allow(unused_variables)]
pub fn bound_value_for_verifier(v: isize, min: isize, max: isize) -> isize {
    #[cfg(target_arch = "bpf")]
    {
        if v < min {
            return min;
        }
        if v > max {
            return max;
        }
    }
    v
}