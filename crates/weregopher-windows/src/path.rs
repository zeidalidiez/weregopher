use std::{io, ptr};

use windows_sys::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};

/// Derives the invariant Windows ordinal uppercase key for a Unicode path.
///
/// Equal keys identify names that Windows ordinal case-insensitive comparison
/// treats as aliases. Callers can sort or index these keys without exporting a
/// raw pointer or locale-dependent comparison callback.
///
/// # Errors
///
/// Returns an error when the input length cannot be represented by Win32, when
/// allocation fails, or when Windows cannot map the string.
#[allow(
    unsafe_code,
    reason = "isolated LCMapStringEx calls over initialized UTF-16 vectors with checked lengths"
)]
pub fn windows_ordinal_case_key(source: &str) -> io::Result<Vec<u16>> {
    if source.is_empty() {
        return Ok(Vec::new());
    }

    let mut source_wide = Vec::new();
    source_wide
        .try_reserve_exact(source.len())
        .map_err(|_| allocation_error("Windows ordinal source key"))?;
    source_wide.extend(source.encode_utf16());
    let source_len = i32::try_from(source_wide.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows ordinal source length exceeds the Win32 limit",
        )
    })?;

    // SAFETY: `source_wide` is initialized for `source_len` UTF-16 units. A null
    // destination with zero length requests the required output size. Reserved
    // parameters are null/zero as required by `LCMapStringEx`.
    let required = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            source_wide.as_ptr(),
            source_len,
            ptr::null_mut(),
            0,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let required = usize::try_from(required).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a negative ordinal key length",
        )
    })?;
    let mut key = Vec::new();
    key.try_reserve_exact(required)
        .map_err(|_| allocation_error("Windows ordinal output key"))?;
    key.resize(required, 0);
    let destination_len = i32::try_from(key.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows ordinal output length exceeds the Win32 limit",
        )
    })?;

    // SAFETY: source storage remains live and initialized. `key` is initialized
    // and writable for exactly `destination_len` UTF-16 units, the size returned
    // by the preceding call using the same source and flags.
    let mapped = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            source_wide.as_ptr(),
            source_len,
            key.as_mut_ptr(),
            destination_len,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if mapped == 0 {
        return Err(io::Error::last_os_error());
    }
    let mapped = usize::try_from(mapped).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a negative mapped ordinal key length",
        )
    })?;
    if mapped > key.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an ordinal key larger than its requested buffer",
        ));
    }
    key.truncate(mapped);
    Ok(key)
}

fn allocation_error(resource: &'static str) -> io::Error {
    io::Error::other(format!("could not allocate {resource}"))
}
