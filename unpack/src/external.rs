//! Locating and running optional external helpers (upx, 7-Zip, innoextract)
//! without a shell and with a hard timeout. None of these execute the sample:
//! they only parse/decompress it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct ToolSpec {
    pub key: &'static str,
    pub env: &'static str,
    pub candidates: &'static [&'static str],
    pub install_hint: &'static str,
}

pub const UPX: ToolSpec = ToolSpec {
    key: "upx",
    env: "MALCHELA_UPX",
    candidates: &["upx", "upx-ucl"],
    install_hint: "brew install upx | apt install upx-ucl | choco install upx",
};

pub const SEVENZIP: ToolSpec = ToolSpec {
    key: "7z",
    env: "MALCHELA_7Z",
    candidates: &["7zz", "7z", "7za"],
    install_hint: "brew install sevenzip | apt install 7zip | choco install 7zip",
};

pub const INNOEXTRACT: ToolSpec = ToolSpec {
    key: "innoextract",
    env: "MALCHELA_INNOEXTRACT",
    candidates: &["innoextract"],
    install_hint: "brew install innoextract | apt install innoextract | choco install innoextract",
};

pub const ALL: &[&ToolSpec] = &[&UPX, &SEVENZIP, &INNOEXTRACT];

fn exe_names(base: &str) -> Vec<String> {
    if cfg!(windows) {
        vec![format!("{}.exe", base), base.to_string()]
    } else {
        vec![base.to_string()]
    }
}

pub fn find(spec: &ToolSpec) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(spec.env) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    // GUI-launched processes on macOS often get a minimal PATH.
    for extra in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "C:\\Program Files\\7-Zip"] {
        dirs.push(PathBuf::from(extra));
    }
    for c in spec.candidates {
        for name in exe_names(c) {
            for d in &dirs {
                let p = d.join(&name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

pub struct RunResult {
    pub ok: bool,
    pub output: String,
}

/// Run `bin args...`, capturing stdout+stderr, killing it after `timeout`.
pub fn run(bin: &Path, args: &[&std::ffi::OsStr], timeout: Duration) -> RunResult {
    let mut child = match Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return RunResult { ok: false, output: format!("failed to start {}: {}", bin.display(), e) },
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return RunResult { ok: false, output: format!("{} timed out after {}s", bin.display(), timeout.as_secs()) };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return RunResult { ok: false, output: e.to_string() },
        }
    }
    match child.wait_with_output() {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.trim().is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(err.trim());
            }
            RunResult { ok: out.status.success(), output: text.trim().to_string() }
        }
        Err(e) => RunResult { ok: false, output: e.to_string() },
    }
}
