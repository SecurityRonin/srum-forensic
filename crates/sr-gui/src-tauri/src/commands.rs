use crate::types::SrumFile;

#[tauri::command]
pub async fn open_file(path: String) -> Result<SrumFile, String> {
    todo!()
}
