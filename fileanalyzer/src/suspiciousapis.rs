

pub fn detect_suspicious_apis(imports: &[String]) -> Vec<String> {
    let suspicious_keywords = [
        "VirtualAlloc", "VirtualFree", "CreateRemoteThread", "WriteProcessMemory",
        "ReadProcessMemory", "WinExec", "ShellExecute", "GetProcAddress", "LoadLibrary",
        "SetWindowsHook", "NtQueryInformation", "ZwQueryInformation", "InternetOpen",
        "InternetReadFile", "WSASocket", "connect", "recv", "send", "RegSetValue", "RegCreateKey"
    ];

    imports
        .iter()
        .filter_map(|import| {
            let import_lower = import.to_lowercase();
            if suspicious_keywords.iter().any(|kw| import_lower.contains(&kw.to_lowercase())) {
                Some(import.clone())
            } else {
                None
            }
        })
        .collect()
}