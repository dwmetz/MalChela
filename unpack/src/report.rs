//! Markdown / plain-text / console rendering of an unpack run.

use crate::detect::Kind;
use crate::engine::{self, Node};

fn human(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// The one-line verdict, also emitted as a marker line in the markdown
/// report so the Analyze rollup can surface it without parsing tables.
pub fn verdict_line(root: &Node) -> String {
    let mut names: Vec<String> = Vec::new();
    engine::walk(root, &mut |n| {
        for v in &n.verdicts {
            if v.kind != Kind::Info && !names.contains(&v.name) {
                names.push(v.name.clone());
            }
        }
    });
    let payloads = engine::payloads(root).len();
    if names.is_empty() {
        "No packing or embedded payloads detected".to_string()
    } else {
        format!(
            "{} — {} payload(s) recovered",
            names.join(", "),
            payloads
        )
    }
}

fn mitre(root: &Node) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut v = Vec::new();
    if engine::packing_found(root) {
        v.push(("T1027.002", "Obfuscated Files or Information: Software Packing", "Stealth"));
    }
    if engine::embedded_found(root) {
        v.push(("T1027.009", "Obfuscated Files or Information: Embedded Payloads", "Stealth"));
    }
    if engine::encoded_found(root) {
        v.push(("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", "Stealth"));
    }
    v
}

fn tree_lines(n: &Node, prefix: &str, last: bool, top: bool, out: &mut Vec<String>) {
    let tags: Vec<String> = n.verdicts.iter().filter(|v| v.kind != Kind::Info).map(|v| v.name.clone()).collect();
    let label = format!(
        "{} [{}]{}{}",
        n.name,
        n.format_label,
        if tags.is_empty() { String::new() } else { format!(" — {}", tags.join(", ")) },
        n.note.as_ref().map(|x| format!(" ({})", x)).unwrap_or_default()
    );
    if top {
        out.push(label);
    } else {
        out.push(format!("{}{}{}", prefix, if last { "└── " } else { "├── " }, label));
    }
    let child_prefix = if top { String::new() } else { format!("{}{}", prefix, if last { "    " } else { "│   " }) };
    for (i, c) in n.children.iter().enumerate() {
        tree_lines(c, &child_prefix, i + 1 == n.children.len(), false, out);
    }
}

pub fn tree(root: &Node) -> String {
    let mut lines = Vec::new();
    tree_lines(root, "", true, true, &mut lines);
    lines.join("\n")
}

pub fn markdown(root: &Node, out_dir: &str) -> String {
    let mut md = String::new();
    md.push_str("# Unpack Report\n\n");
    md.push_str(&format!("**File:** `{}`  \n", root.path));
    md.push_str(&format!("**SHA256:** `{}`  \n", root.sha256));
    md.push_str(&format!("**Format:** {}  \n", root.format_label));
    md.push_str(&format!("**Size:** {} ({} bytes), entropy {:.2}  \n", human(root.size), root.size, root.entropy));
    md.push_str(&format!("**Packer verdict:** {}  \n", verdict_line(root)));
    let payloads = engine::payloads(root);
    if !payloads.is_empty() {
        md.push_str(&format!("**Output directory:** `{}`  \n", out_dir));
    }
    md.push('\n');

    // Detections across all layers
    let mut det = Vec::new();
    engine::walk(root, &mut |n| {
        for v in &n.verdicts {
            det.push((n.depth, n.name.clone(), v.clone()));
        }
    });
    md.push_str("## Detections\n\n");
    if det.is_empty() {
        md.push_str("No packers, protectors, installers, or embedded payloads detected.\n\n");
    } else {
        md.push_str("| Layer | File | Detection | Type | Confidence | Evidence |\n|---|---|---|---|---|---|\n");
        for (d, f, v) in &det {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} |\n",
                d,
                md_cell(f),
                md_cell(&v.name),
                v.kind.label(),
                v.confidence,
                md_cell(&v.evidence.join("; "))
            ));
        }
        md.push('\n');
        let advice: Vec<String> = det
            .iter()
            .filter_map(|(_, f, v)| v.advice.as_ref().map(|a| format!("- **{}** (`{}`): {}", v.name, f, a)))
            .collect();
        if !advice.is_empty() {
            md.push_str("### Notes\n\n");
            md.push_str(&advice.join("\n"));
            md.push_str("\n\n");
        }
    }

    let mut acts = Vec::new();
    engine::walk(root, &mut |n| {
        for a in &n.actions {
            acts.push((n.depth, n.name.clone(), a.clone()));
        }
    });
    if !acts.is_empty() {
        md.push_str("## Actions\n\n| Layer | File | Handler | Status | Detail |\n|---|---|---|---|---|\n");
        for (d, f, a) in &acts {
            md.push_str(&format!("| {} | `{}` | {} | {} | {} |\n", d, md_cell(f), a.handler, a.status, md_cell(&a.message)));
        }
        md.push('\n');
    }

    if !payloads.is_empty() {
        md.push_str("## Recovered Payloads\n\n| Layer | File | Format | Size | SHA256 | Source |\n|---|---|---|---|---|---|\n");
        for p in &payloads {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} | `{}` | {} |\n",
                p.depth,
                md_cell(&p.path),
                p.format_label,
                human(p.size),
                p.sha256,
                md_cell(p.source.as_deref().unwrap_or(""))
            ));
        }
        md.push_str("\n_Run File Analyzer / mStrings / Mach-O Info against the recovered payloads — or point Analyze at the original sample, which does this automatically._\n\n");
    }

    if !root.children.is_empty() {
        md.push_str("## Layer Tree\n\n```text\n");
        md.push_str(&tree(root));
        md.push_str("\n```\n\n");
    }

    if !root.sections.is_empty() {
        md.push_str("## Section Entropy (input)\n\n| Section | Raw Size | Entropy | Flags |\n|---|---|---|---|\n");
        for s in root.sections.iter().take(40) {
            md.push_str(&format!(
                "| `{}` | {} | {:.2}{} | {} |\n",
                md_cell(&s.name),
                s.raw_size,
                s.entropy,
                if s.entropy >= 7.2 && s.raw_size >= 4096 { " ⚠" } else { "" },
                s.flags
            ));
        }
        if let Some((off, size)) = root.overlay {
            md.push_str(&format!("\nOverlay: {} bytes at `{:#x}`\n", size, off));
        }
        md.push('\n');
    }

    let m = mitre(root);
    if !m.is_empty() {
        md.push_str("## MITRE ATT&CK\n\n| ID | Technique | Tactic |\n|---|---|---|\n");
        for (id, name, tactic) in m {
            md.push_str(&format!("| {} | {} | {} |\n", id, name, tactic));
        }
        md.push('\n');
    }
    md
}

pub fn console(root: &Node, out_dir: &str) -> String {
    use common_ui::styled_line;
    let mut s = String::new();
    let push = |s: &mut String, tag: &str, line: &str| {
        s.push_str(&styled_line(tag, line));
        s.push('\n');
    };
    push(&mut s, "yellow", "Unpack");
    push(&mut s, "stone", &format!("File:    {}", root.path));
    push(&mut s, "stone", &format!("SHA256:  {}", root.sha256));
    push(&mut s, "stone", &format!("Format:  {}  |  {}  |  entropy {:.2}", root.format_label, human(root.size), root.entropy));
    s.push('\n');

    let mut any = false;
    engine::walk(root, &mut |n| {
        for v in &n.verdicts {
            any = true;
            let tag = match v.kind {
                Kind::Packer | Kind::Protector | Kind::Crypter => "red",
                Kind::Heuristic | Kind::Embedded | Kind::Installer | Kind::Bundler => "yellow",
                _ => "stone",
            };
            push(&mut s, tag, &format!("[{}] {} — {} ({}){}", n.depth, v.name, v.kind.label(), v.confidence, if n.depth > 0 { format!("  in {}", n.name) } else { String::new() }));
            for e in &v.evidence {
                push(&mut s, "stone", &format!("      • {}", e));
            }
            if let Some(a) = &v.advice {
                push(&mut s, "NOTE", &format!("      → {}", a));
            }
        }
        for a in &n.actions {
            let tag = match a.status.as_str() {
                "ok" => "green",
                "partial" | "skipped" => "yellow",
                _ => "red",
            };
            push(&mut s, tag, &format!("      {} [{}]: {}", a.handler, a.status, a.message));
        }
    });
    if !any {
        push(&mut s, "green", "No packing or embedded payloads detected.");
    }
    let payloads = engine::payloads(root);
    if !payloads.is_empty() {
        s.push('\n');
        push(&mut s, "yellow", &format!("Recovered {} payload(s) → {}", payloads.len(), out_dir));
        for line in tree(root).lines() {
            push(&mut s, "highlight", &format!("  {}", line));
        }
    }
    for (id, name, _) in mitre(root) {
        push(&mut s, "NOTE", &format!("MITRE: {} {}", id, name));
    }
    s
}

/// console() with colour codes / GUI tags removed, for .txt reports.
pub fn plain(root: &Node, out_dir: &str) -> String {
    strip_tags(&console(root, out_dir))
}

fn strip_tags(s: &str) -> String {
    s.lines()
        .map(|l| {
            let l = strip_ansi(l);
            if l.starts_with('[') {
                if let Some(end) = l.find(']') {
                    let tag = &l[1..end];
                    if tag.chars().all(|c| c.is_ascii_alphabetic()) && !tag.is_empty() {
                        return l[end + 1..].to_string();
                    }
                }
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if it.peek() == Some(&'[') {
                it.next();
                for c2 in it.by_ref() {
                    if c2.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}
