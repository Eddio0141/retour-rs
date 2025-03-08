use crate::error::Result;

/// Returns true if an address is executable.
pub fn is_executable_address(address: *const ()) -> Result<bool> {
  Ok(
    region::query(address as *const _)?
      .protection()
      .contains(region::Protection::EXECUTE),
  )
}

pub const BITNESS: u32 = (std::mem::size_of::<usize>() * 8) as u32;
