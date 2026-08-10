use retour::Result;
use std::mem;

type FnAdd = extern "C" fn(i32, i32) -> i32;

#[inline(never)]
extern "C" fn sub_detour(x: i32, y: i32) -> i32 {
  unsafe { std::ptr::read_volatile(&x as *const i32) - y }
}

#[inline(never)]
fn hook_callback() {}

mod raw {
  use core::slice;
  use std::arch::asm;

  use super::*;
  use retour::{RawDetour, RawHook};

  #[test]
  fn detour() -> Result<()> {
    #[inline(never)]
    extern "C" fn add(x: i32, y: i32) -> i32 {
      unsafe { std::ptr::read_volatile(&x as *const i32) + y }
    }

    unsafe {
      let hook = RawDetour::new(add as *const (), sub_detour as *const ())
        .expect("target or source is not usable for detouring");

      assert_eq!(add(10, 5), 15);
      assert!(!hook.is_enabled());

      hook.enable()?;
      {
        assert!(hook.is_enabled());

        // The `add` function is hooked, but can be called using the trampoline
        let trampoline: FnAdd = mem::transmute(hook.trampoline());

        // Call the original function
        assert_eq!(trampoline(10, 5), 15);

        // Call the hooked function (i.e `add → sub_detour`)
        assert_eq!(add(10, 5), 5);
      }
      hook.disable()?;

      // With the hook disabled, the function is restored
      assert!(!hook.is_enabled());
      assert_eq!(add(10, 5), 15);
    }
    Ok(())
  }

  #[test]
  #[allow(static_mut_refs)]
  fn func_hook() {
    static mut COUNTER: usize = 0;

    #[inline(never)]
    unsafe extern "C" fn count() {
      unsafe {
        asm!(
          "inc {}",
          inout(reg) COUNTER
        )
      }
    }

    // Hook on `inc`
    let count_slice = unsafe { slice::from_raw_parts(count as *const u8, 1000) };
    let count_addr = {
      cfg_select! {
        any(target_arch = "x86", target_arch = "x86_64") => {
          use iced_x86::*;

          let mut decoder = Decoder::with_ip(usize::BITS, count_slice, count as *const () as u64, DecoderOptions::NONE);

          let mut inst = Instruction::default();

          while decoder.can_decode() {
            decoder.decode_out(&mut inst);

            if inst.mnemonic() == Mnemonic::Inc {
              break;
            }
          }

          assert_eq!(inst.mnemonic(), Mnemonic::Inc);

          decoder.ip() as usize
        }
        _ => compiler_error!("func_hook test not implemented for this architecture")
      }
    };

    unsafe {
      let hook = RawHook::new(count_addr, hook_callback as *const (), false).unwrap();

      hook.enable().unwrap();

      let counter_prev = COUNTER;
      count();
      assert_eq!(COUNTER, counter_prev.wrapping_add(1));

      hook.disable().unwrap();
    }
  }
}

mod generic {
  use super::*;
  use retour::GenericDetour;

  #[test]
  fn test() -> Result<()> {
    #[inline(never)]
    extern "C" fn add(x: i32, y: i32) -> i32 {
      unsafe { std::ptr::read_volatile(&x as *const i32) + y }
    }

    unsafe {
      let hook = GenericDetour::<FnAdd>::new(add, sub_detour)
        .expect("target or source is not usable for detouring");

      assert_eq!(add(10, 5), 15);
      assert_eq!(hook.call(10, 5), 15);
      hook.enable()?;
      {
        assert_eq!(hook.call(10, 5), 15);
        assert_eq!(add(10, 5), 5);
      }
      hook.disable()?;
      assert_eq!(hook.call(10, 5), 15);
      assert_eq!(add(10, 5), 15);
    }
    Ok(())
  }
}

#[cfg(feature = "static-detour")]
mod statik {
  use super::*;
  use retour::static_detour;

  #[inline(never)]
  unsafe extern "C" fn add(x: i32, y: i32) -> i32 {
    std::ptr::read_volatile(&x as *const i32) + y
  }

  static_detour! {
    #[doc="Test with attributes"]
    pub static DetourAdd: unsafe extern "C" fn(i32, i32) -> i32;
  }

  #[test]
  fn test() -> Result<()> {
    unsafe {
      DetourAdd.initialize(add, |x, y| x - y)?;

      assert_eq!(add(10, 5), 15);
      assert_eq!(DetourAdd.is_enabled(), false);

      DetourAdd.enable()?;
      {
        assert!(DetourAdd.is_enabled());
        assert_eq!(DetourAdd.call(10, 5), 15);
        assert_eq!(add(10, 5), 5);
      }
      DetourAdd.disable()?;

      assert_eq!(DetourAdd.is_enabled(), false);
      assert_eq!(DetourAdd.call(10, 5), 15);
      assert_eq!(add(10, 5), 15);
    }
    Ok(())
  }
}

#[cfg(feature = "28-args")]
mod args_28 {
  use super::*;
  use retour::GenericDetour;

  type I = i32;
  type BigFn = fn(I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I);

  fn a(
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
  ) {
  }
  fn b(
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
  ) {
  }
  #[test]
  fn sanity_check() -> Result<()> {
    let hook = unsafe { GenericDetour::<BigFn>::new(a, b) };
    Ok(())
  }
}
#[cfg(feature = "42-args")]
mod args_42 {
  use super::*;
  use retour::GenericDetour;

  type I = i32;
  type BiggerFn = fn(
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
    I,
  );

  fn a(
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
  ) {
  }
  fn b(
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
    _: I,
  ) {
  }
  #[test]
  fn sanity_check() -> Result<()> {
    let hook = unsafe { GenericDetour::<BiggerFn>::new(a, b)? };
    Ok(())
  }
}

#[cfg(target_arch = "x86_64")]
mod relative_ip {
  use super::*;
  use retour::GenericDetour;
  use std::arch::global_asm;

  static VALUE: i32 = 3;

  global_asm!(r#"
      .global check_value
      check_value:
        cmp  dword ptr [rip - {value}], 5   // 83 3D XX XX XX XX 05 // XX - displacement bytes
        setz al                             // 0F 94 C0
        and  al, 1                          // 24 01
        ret                                 // C3
    "#,
    value = sym VALUE,
  );

  type FnCheckValue = extern "C" fn() -> bool;

  unsafe extern "C" {
    safe fn check_value() -> bool;
  }

  extern "C" fn new_check_value() -> bool {
    true
  }

  #[test]
  fn test() -> Result<()> {
    unsafe {
      let hook = GenericDetour::<FnCheckValue>::new(check_value, new_check_value)
        .expect("target or source is not usable for detouring");

      assert_eq!(check_value(), false);
      assert_eq!(hook.call(), false);
      hook.enable()?;
      {
        assert_eq!(hook.call(), false);
        assert_eq!(check_value(), true);
      }
      hook.disable()?;
      assert_eq!(hook.call(), false);
      assert_eq!(check_value(), false);
    }

    Ok(())
  }
}
