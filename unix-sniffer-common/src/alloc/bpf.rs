use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, PerCpuHashMap},
};
use core::{mem, result};

const MAX_HEAP_SIZE: usize = 4096; 

const fn max(a: usize, b: usize) -> usize {
    if a < b {
        return b;
    }
    a
}

macro_rules! max {
    ($a:expr) => ($a);
    ($a:expr, $($rest:expr),*) => {{max($a, max!($($rest),*))}};
}

const MAX_ALLOCS: u32 = 8;


const HEAP_MAX_ALLOC_SIZE: usize = MAX_HEAP_SIZE * 2;

const ZEROS: [u8; HEAP_MAX_ALLOC_SIZE] = [0; HEAP_MAX_ALLOC_SIZE];


#[map]
static mut HEAP: PerCpuHashMap<u32, [u8; HEAP_MAX_ALLOC_SIZE]> =
    PerCpuHashMap::with_max_entries(MAX_ALLOCS, 0);

#[map]
static mut ALLOCATOR: PerCpuArray<Allocator> = PerCpuArray::with_max_entries(1, 0);

pub struct Allocator {
    pub i_next: u32,
}

type Result<T> = result::Result<T, u32>;

#[inline(always)]
pub fn init() -> Result<()> {
    Allocator::new()?;
    Ok(())
}

#[inline(always)]
pub fn alloc_zero<T>() -> Result<&'static mut T> {
    let alloc = Allocator::reuse()?;
    alloc.zero_alloc::<T>()
}

impl Allocator {
    fn new() -> Result<&'static mut Self> {
        let a = Self::reuse()?;
        a.i_next = 0;
        Ok(a)
    }

    fn reuse() -> Result<&'static mut Self> {
        unsafe {
            let ptr = ALLOCATOR
                .get_ptr_mut(0)
                .ok_or(1u32)?;
            let a = &mut *ptr;
            Ok(a)
        }
    }

    fn alloc_slice<T>(&mut self) -> Result<&'static mut [u8]> {
        let sizeof = mem::size_of::<T>();

        if self.i_next == MAX_ALLOCS {
            return Err(1u32);
        }

        unsafe {
            let k = self.i_next;
            HEAP.insert(&k, &ZEROS, 0)
                .map_err(|_| 1u32)?;

            if let Some(alloc) = HEAP.get_ptr_mut(&k).and_then(|a| a.as_mut()) {
                if sizeof > alloc.len() {
                    return Err(1u32);
                }

                self.i_next += 1;

                return Ok(alloc);
            }
        }

        Err(1u32)
    }

    fn zero_alloc<T>(&mut self) -> Result<&'static mut T> {
        unsafe {
            let alloc = self.alloc_slice::<T>()?;
            Ok(core::mem::transmute(alloc.as_mut_ptr()))
        }
    }
}