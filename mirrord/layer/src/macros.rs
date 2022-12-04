#[macro_export]
macro_rules! replace {
    ($interceptor:expr, $detour_name:expr, $detour_function:expr, $detour_type:ty, $hook_fn:expr, $module_name:expr) => {{
        let intercept = |interceptor: &mut frida_gum::interceptor::Interceptor,
                         symbol_name,
                         module_name: Option<&str>,
                         detour: $detour_type|
         -> $crate::error::Result<$detour_type> {
            tracing::trace!("replace -> hooking {:#?}", $detour_name);

            let function = frida_gum::Module::find_export_by_name(module_name, symbol_name).ok_or(
                $crate::error::LayerError::NoExportName(symbol_name.to_string()),
            )?;

            let replaced = interceptor.replace(
                function,
                frida_gum::NativePointer(detour as *mut libc::c_void),
                frida_gum::NativePointer(std::ptr::null_mut()),
            )?;

            let original_fn: $detour_type = std::mem::transmute(replaced);

            Ok(original_fn)
        };

        match intercept($interceptor, $detour_name, $module_name, $detour_function) {
            Ok(hooked) => {
                $hook_fn.set(hooked).unwrap();
                tracing::trace!(
                    "replace -> hooked {:#?} at {:#?}",
                    $detour_name,
                    $module_name
                );
            }
            Err(err) => {
                tracing::trace!(
                    "failed replace {:#?} at {:#?} with err {:#?}",
                    $detour_name,
                    $module_name,
                    err
                );
            }
        }
    }};
}

#[macro_export]
macro_rules! replace_symbol {
    ($interceptor:expr, $detour_name:expr, $detour_function:expr, $detour_type:ty, $hook_fn:expr, $binary:expr) => {{
        let intercept = |interceptor: &mut frida_gum::interceptor::Interceptor,
                         symbol_name,
                         detour: $detour_type,
                         binary: &str|
         -> $crate::error::Result<$detour_type> {
            tracing::info!("replace -> hooking {:#?}", $detour_name);

            let function = frida_gum::Module::find_symbol_by_name(binary, symbol_name).ok_or(
                $crate::error::LayerError::NoExportName(symbol_name.to_string()),
            )?;

            let replaced = interceptor.replace(
                function,
                frida_gum::NativePointer(detour as *mut libc::c_void),
                frida_gum::NativePointer(std::ptr::null_mut()),
            );

            tracing::trace!(
                "replace -> hooked {:#?} {:#?}",
                $detour_name,
                replaced.is_ok()
            );

            let original_fn: $detour_type = std::mem::transmute(replaced?);

            Ok(original_fn)
        };

        intercept($interceptor, $detour_name, $detour_function, $binary)
            .and_then(|hooked| Ok($hook_fn.set(hooked).unwrap()))
    }};
}

#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
macro_rules! hook_symbol {
    ($interceptor:expr, $func:expr, $detour_name:expr, $binary:expr) => {
        if let Some(symbol) = frida_gum::Module::find_symbol_by_name($binary, $func) {
            match $interceptor.replace(
                symbol,
                frida_gum::NativePointer($detour_name as *mut libc::c_void),
                frida_gum::NativePointer(std::ptr::null_mut::<libc::c_void>()),
            ) {
                Err(e) => {
                    tracing::warn!("{} error: {:?}", $func, e);
                }
                Ok(_) => {
                    tracing::trace!("{} hooked", $func);
                }
            }
        };
    };
}

#[macro_export]
macro_rules! graceful_exit {
    ($($arg:tt)+) => {{
        eprintln!($($arg)+);
        graceful_exit!()
    }};
    () => {{
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(std::process::id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .expect("unable to graceful exit");
        panic!()
    }};
}

#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
pub(crate) use hook_symbol;
