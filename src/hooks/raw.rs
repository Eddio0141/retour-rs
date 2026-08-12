use crate::arch::Detour;

use crate::error::Result;

#[derive(Debug)]
pub struct RawHook(Detour);

// TODO: stop all threads in target during patch?
impl RawHook {
  /// Constructs a new function hook.
  ///
  /// The hook is disabled by default.
  pub unsafe fn new(target: usize, hook: *const ()) -> Result<Self> {
    Detour::new(target as *const (), hook, true).map(RawHook)
  }

  /// Enables the detour.
  pub unsafe fn enable(&self) -> Result<()> {
    self.0.enable()
  }

  /// Disables the detour.
  pub unsafe fn disable(&self) -> Result<()> {
    self.0.disable()
  }

  /// Returns whether the detour is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.0.is_enabled()
  }
}

unsafe impl Send for RawHook {}
unsafe impl Sync for RawHook {}
