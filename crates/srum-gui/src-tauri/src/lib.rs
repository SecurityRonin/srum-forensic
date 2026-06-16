mod commands;
mod timeline;
pub mod types;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![commands::open_file])
        .run(tauri::generate_context!())
        .expect("error running SRUM Examiner");
}
