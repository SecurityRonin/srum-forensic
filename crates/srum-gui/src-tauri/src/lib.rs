#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
mod commands;
mod timeline;
pub mod types;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![commands::open_file])
        .run(tauri::generate_context!());
    if let Err(e) = result {
        eprintln!("SRUM Examiner failed to start: {e}");
    }
}
