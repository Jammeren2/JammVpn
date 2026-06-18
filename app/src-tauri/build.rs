fn main() {
    // WinDivert.dll подключаем через DELAY-LOAD: DLL грузится не на старте, а при
    // первом вызове WinDivert (внутри split). Это позволяет хранить DLL вшитым в
    // exe и распаковывать его рядом РОВНО перед использованием (single-exe), а
    // также избегает падения старта от статической линковки user-mode WinDivert.
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-arg=/DELAYLOAD:WinDivert.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    }
    tauri_build::build()
}
