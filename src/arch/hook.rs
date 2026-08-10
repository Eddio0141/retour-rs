use std::{
  cell::UnsafeCell,
  fmt,
  sync::atomic::{AtomicBool, Ordering},
};

use crate::{alloc, arch, util, Error};

use crate::error::Result;

use super::memory;

/// An architecture-independent implementation of a function hook.
pub struct Hook {
  hook: alloc::ExecutableMemory,
  patcher: UnsafeCell<arch::Patcher>,
  enabled: AtomicBool,
}

impl Hook {
  // `target` is usize as it doesn't have to be at the start of the function
  pub unsafe fn new(target: usize, hook: *const ()) -> Result<Self> {
    let target = target as *const ();

    if target == hook {
      Err(Error::SameAddress)?;
    }

    // Lock this so OS operations are not performed in parallell
    let mut pool = memory::POOL.lock().unwrap();

    if !util::is_executable_address(target)? || !util::is_executable_address(hook)? {
      Err(Error::NotExecutable)?;
    }

    // Create a hook generator for the target function
    let margin = arch::meta::prolog_margin(target);
    let hook = arch::HookArch::new(target, hook)?;
    let hook = memory::allocate_pic(&mut pool, hook.emitter(), target)?;

    Ok(Hook {
      patcher: UnsafeCell::new(arch::Patcher::new(target, (*hook).as_ptr().cast(), 5)?),
      hook,
      enabled: AtomicBool::default(),
    })
  }

  /// Enables the hook.
  pub unsafe fn enable(&self) -> Result<()> {
    self.toggle(true)
  }

  /// Disables the hook.
  pub unsafe fn disable(&self) -> Result<()> {
    self.toggle(false)
  }

  /// Returns whether the hook is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.enabled.load(Ordering::SeqCst)
  }

  /// Enables or disables the hook.
  unsafe fn toggle(&self, enabled: bool) -> Result<()> {
    let _guard = memory::POOL.lock().unwrap();

    if self.enabled.load(Ordering::SeqCst) == enabled {
      return Ok(());
    }

    // Runtime code is by default only read-execute
    let _handle = {
      let area = (*self.patcher.get()).area();
      region::protect_with_handle(
        area.as_ptr(),
        area.len(),
        region::Protection::READ_WRITE_EXECUTE,
      )
    }?;

    // Copy either the hook or the original bytes of the function
    (*self.patcher.get()).toggle(enabled);
    self.enabled.store(enabled, Ordering::SeqCst);
    Ok(())
  }
}

impl fmt::Debug for Hook {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "Hook {{ enabled: {}, hook: {:x} }}",
      self.is_enabled(),
      self.hook.as_ptr() as usize
    )
  }
}
