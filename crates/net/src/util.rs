//! Внутренние утилиты сетевого ядра.
//!
//! `allocate_vec` портирован из cfal/shoes `src/util.rs` (MIT © Alex Lau).

/// Аллоцирует `Vec<T>` заданной длины без инициализации.
///
/// Используется для байтовых буферов, которые полностью перезаписываются до
/// чтения (как в исходном коде shoes).
#[allow(clippy::uninit_vec)]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    // SAFETY: буфер полностью заполняется вызывающим кодом до чтения.
    unsafe {
        ret.set_len(len);
    }
    ret
}
