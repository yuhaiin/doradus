use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn escape_rust(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == ".gitkeep") {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, files);
        } else if path.is_file() {
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            files.push((relative.to_string_lossy().replace('\\', "/"), path));
        }
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let web_root = manifest_dir.join("web");
    println!("cargo:rerun-if-changed={}", web_root.display());

    let mut files = Vec::new();
    if web_root.is_dir() {
        collect_files(&web_root, &web_root, &mut files);
        files.sort_by(|left, right| left.0.cmp(&right.0));
    }

    let mut generated = String::from(concat!(
        "pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {\n",
        "    FILES.iter().find(|(name, _)| *name == path).map(|(_, bytes)| (*bytes, content_type(path)))\n",
        "}\n\n",
        "fn content_type(path: &str) -> &'static str {\n",
        "    match path.rsplit_once('.').map(|(_, extension)| extension) {\n",
        "        Some(\"html\") => \"text/html; charset=utf-8\",\n",
        "        Some(\"css\") => \"text/css; charset=utf-8\",\n",
        "        Some(\"js\") | Some(\"mjs\") => \"text/javascript; charset=utf-8\",\n",
        "        Some(\"json\") => \"application/json\",\n",
        "        Some(\"svg\") => \"image/svg+xml\",\n",
        "        Some(\"ico\") => \"image/x-icon\",\n",
        "        Some(\"png\") => \"image/png\",\n",
        "        Some(\"jpg\") | Some(\"jpeg\") => \"image/jpeg\",\n",
        "        Some(\"webp\") => \"image/webp\",\n",
        "        Some(\"woff\") => \"font/woff\",\n",
        "        Some(\"woff2\") => \"font/woff2\",\n",
        "        _ => \"application/octet-stream\",\n",
        "    }\n",
        "}\n\n",
        "static FILES: &[(&str, &[u8])] = &[\n",
    ));
    for (relative, path) in files {
        generated.push_str(&format!(
            "    (\"{}\", include_bytes!(\"{}\")),\n",
            escape_rust(&relative),
            escape_rust(&path.to_string_lossy()),
        ));
    }
    generated.push_str("];\n");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out_dir.join("embedded_web.rs"), generated).unwrap();
}
