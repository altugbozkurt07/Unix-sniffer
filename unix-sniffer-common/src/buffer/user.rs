use super::Buffer;

impl<const N: usize> Buffer<N> {
    pub fn convert_to_byte_array(&self) -> Vec<&u8>{
        self.as_slice()
        .into_iter()
        .skip_while(|&byte| *byte == b'\0')
        .collect::<Vec<_>>()
    }
}