// Copyright © SixtyFPS GmbH <info@slint.dev>
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

//! Generate a third-party license listing.
//!
//! This is a self-contained replacement for `cargo about`. It fetches the
//! dependencies into the cargo cache (`cargo fetch`), resolves the dependency
//! graph across all target platforms via `cargo metadata`, restricting it to
//! the features actually enabled in the analyzed crate, and then harvests the
//! license texts directly from the crate sources in the cache.

// cSpell: ignore noassertion licence rsplit

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// SPDX license identifiers we accept for third-party dependencies. A crate is
/// rejected unless its license expression is satisfiable by this set.
const ACCEPTED: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "MPL-2.0",
    "Zlib",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "CC0-1.0",
    "BSL-1.0",
    "ISC",
    "Unicode-DFS-2016",
    "Unicode-3.0",
    "OpenSSL",
    "Unlicense",
    "WTFPL",
    "LicenseRef-Slint-Software-3.0",
];

/// Skip dependencies reachable only through dev-dependency edges.
const IGNORE_DEV_DEPENDENCIES: bool = true;

/// Silently drop crates without any license information instead of failing.
const FILTER_NOASSERTION: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Html,
    /// `cargo about`-compatible JSON, consumed by the docs site generators.
    Json,
}

#[derive(Debug, clap::Parser)]
pub struct LicenseCommand {
    /// Path to the `Cargo.toml` whose dependencies should be analyzed.
    /// Defaults to `Cargo.toml` in the current directory.
    #[arg(long)]
    manifest_path: Option<PathBuf>,
    /// Comma-separated features to enable on the analyzed crate (repeatable).
    #[arg(long, value_delimiter = ',')]
    features: Vec<String>,
    /// Do not enable the analyzed crate's default features.
    #[arg(long)]
    no_default_features: bool,
    /// Enable all features of the analyzed crate.
    #[arg(long)]
    all_features: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Html)]
    format: Format,
    /// Where to write the result. Writes to stdout when omitted.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

impl LicenseCommand {
    pub fn run(&self) -> anyhow::Result<()> {
        let manifest_path = match &self.manifest_path {
            Some(p) => std::env::current_dir()?.join(p),
            None => std::env::current_dir()?.join("Cargo.toml"),
        };
        generate(&GenerateArgs {
            manifest_path,
            features: Features {
                features: self.features.clone(),
                no_default_features: self.no_default_features,
                all_features: self.all_features,
            },
            format: self.format,
            output: self.output.clone(),
        })
    }
}

/// Which features to enable on the analyzed crate, mirroring cargo's flags.
#[derive(Debug, Default)]
pub struct Features {
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub all_features: bool,
}

pub struct GenerateArgs {
    pub manifest_path: PathBuf,
    pub features: Features,
    pub format: Format,
    pub output: Option<PathBuf>,
}

pub fn generate(args: &GenerateArgs) -> anyhow::Result<()> {
    let accepted: HashSet<&str> = ACCEPTED.iter().copied().collect();

    fetch_dependencies(&args.manifest_path)?;

    let packages = resolve_packages(&args.manifest_path, &args.features)?;

    // Collect, per crate, the license ids that apply to it (filtered to the
    // accepted set), and accumulate the license -> crates and license -> texts
    // relationships.
    let mut used_by: BTreeMap<String, Vec<CrateRef>> = BTreeMap::new();
    let mut license_names: BTreeMap<String, String> = BTreeMap::new();
    // license id -> normalized text -> number of crates contributing it
    let mut harvested: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for pkg in &packages {
        let Some(expression) = pkg.license.clone() else {
            // No license information. With FILTER_NOASSERTION this is silently
            // dropped, otherwise it is an error.
            if FILTER_NOASSERTION {
                continue;
            }
            bail!("Crate {} {} has no license information", pkg.name, pkg.version);
        };

        // Lax parsing accepts the deprecated `/` OR-separator and imprecise
        // identifiers (e.g. `apache2`) still found in older crates.
        let expr =
            spdx::Expression::parse_mode(&expression, spdx::ParseMode::LAX).with_context(|| {
                format!("Cannot parse license `{expression}` of {} {}", pkg.name, pkg.version)
            })?;

        if !expr.evaluate(|req| accepted.contains(license_string(req).as_str())) {
            bail!(
                "License `{expression}` of crate {} {} is not in the accepted list",
                pkg.name,
                pkg.version
            );
        }

        let crate_dir = pkg.manifest_path.parent().expect("manifest has a parent");
        let files = license_files(crate_dir.as_std_path());

        // A crate is listed under every accepted license id mentioned in its
        // expression. For `A OR B` where both are accepted, it appears under
        // both; for `A AND B` likewise.
        let ids: BTreeSet<(String, String)> = expr
            .requirements()
            .filter_map(|r| {
                let id = license_string(&r.req);
                accepted.contains(id.as_str()).then(|| (id, license_full_name(&r.req)))
            })
            .collect();

        for (id, full_name) in ids {
            used_by.entry(id.clone()).or_default().push(CrateRef {
                name: pkg.name.clone(),
                version: pkg.version.to_string(),
                repository: pkg.repository.clone(),
            });
            license_names.entry(id.clone()).or_insert(full_name);

            if let Some(text) = find_license_text(&id, &files) {
                *harvested.entry(id).or_default().entry(normalize(&text)).or_default() += 1;
            }
        }
    }

    // Build the final per-license sections.
    let mut sections: Vec<LicenseSection> = used_by
        .into_iter()
        .map(|(id, mut crates)| {
            crates.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
            crates.dedup_by(|a, b| a.name == b.name && a.version == b.version);
            let text = representative_text(&id, harvested.get(&id));
            LicenseSection {
                name: license_names.remove(&id).unwrap_or_else(|| id.clone()),
                count: crates.len(),
                id,
                text,
                used_by: crates,
            }
        })
        .collect();
    sections.sort_by(|a, b| a.name.cmp(&b.name));

    let rendered = match args.format {
        Format::Html => render_html(&sections),
        Format::Json => render_json(&sections),
    };

    match &args.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, rendered)
                .with_context(|| format!("Cannot write {}", path.display()))?;
        }
        None => print!("{rendered}"),
    }

    Ok(())
}

struct CrateRef {
    name: String,
    version: String,
    repository: Option<String>,
}

struct LicenseSection {
    id: String,
    name: String,
    text: String,
    count: usize,
    used_by: Vec<CrateRef>,
}

/// Run `cargo fetch` (for all targets) so that the relevant crate sources are
/// present in the cargo cache before we harvest from it.
fn fetch_dependencies(manifest_path: &Path) -> anyhow::Result<()> {
    let manifest = manifest_path.to_str().context("Non-UTF-8 manifest path")?;
    run_cargo(&["fetch", "--manifest-path", manifest])?;
    Ok(())
}

fn run_cargo(args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(std::env::var("CARGO").as_deref().unwrap_or("cargo"))
        .args(args)
        .status()
        .with_context(|| format!("Failed to run cargo {}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed", args.join(" "));
    }
    Ok(())
}

/// Resolve the dependency packages across all target platforms, restricted to
/// the features enabled in the analyzed crate and honoring
/// `IGNORE_DEV_DEPENDENCIES`.
///
/// `cargo metadata` is run without `--filter-platform`, so its resolve graph
/// spans every target. Its graph keeps optional dependencies even when no
/// active feature enables them, so the walk follows only the edges that the
/// resolved feature set of each crate actually activates.
fn resolve_packages(
    manifest_path: &Path,
    features: &Features,
) -> anyhow::Result<Vec<cargo_metadata::Package>> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.manifest_path(manifest_path);
    if !features.features.is_empty() {
        cmd.features(cargo_metadata::CargoOpt::SomeFeatures(features.features.clone()));
    }
    if features.no_default_features {
        cmd.features(cargo_metadata::CargoOpt::NoDefaultFeatures);
    }
    if features.all_features {
        cmd.features(cargo_metadata::CargoOpt::AllFeatures);
    }
    let metadata = cmd.exec()?;

    let packages: HashMap<cargo_metadata::PackageId, cargo_metadata::Package> =
        metadata.packages.iter().map(|p| (p.id.clone(), p.clone())).collect();

    let resolve = metadata.resolve.context("cargo metadata returned no resolve graph")?;
    let nodes: HashMap<_, _> = resolve.nodes.iter().map(|n| (n.id.clone(), n)).collect();

    // Seed the walk with the package the manifest points at. For a virtual
    // workspace manifest there is no single root, so fall back to all members.
    // Seeding from `resolve.root` (rather than every workspace member) ensures
    // we only consider the dependencies of the analyzed crate, not those of
    // unrelated examples elsewhere in the workspace.
    let mut stack: Vec<_> = match resolve.root.clone() {
        Some(root) => vec![root],
        None => metadata.workspace_members.clone(),
    };
    let mut wanted: BTreeSet<cargo_metadata::PackageId> = BTreeSet::new();
    let mut seen: HashSet<cargo_metadata::PackageId> = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        wanted.insert(id.clone());
        let (Some(node), Some(parent)) = (nodes.get(&id), packages.get(&id)) else { continue };
        let active: HashSet<&str> = node.features.iter().map(String::as_str).collect();
        for dep in &node.deps {
            let non_dev: Vec<_> = dep
                .dep_kinds
                .iter()
                .filter(|k| k.kind != cargo_metadata::DependencyKind::Development)
                .collect();
            // Drop dev-only edges.
            if IGNORE_DEV_DEPENDENCIES && !dep.dep_kinds.is_empty() && non_dev.is_empty() {
                continue;
            }
            // Drop edges that only exist under a synthetic build cfg such as
            // `cfg(fuzzing)`, `cfg(test)` or `cfg(miri)`. Those are never active
            // in a normal build for any real target platform.
            if !non_dev.is_empty()
                && non_dev
                    .iter()
                    .all(|k| k.target.as_ref().is_some_and(|t| is_synthetic_cfg(&t.to_string())))
            {
                continue;
            }
            let Some(dep_pkg) = packages.get(&dep.pkg) else { continue };
            if dependency_enabled(parent, &active, dep_pkg.name.as_str()) {
                stack.push(dep.pkg.clone());
            }
        }
    }

    let mut packages = packages;
    Ok(wanted.into_iter().filter_map(|id| packages.remove(&id)).collect())
}

/// Whether a `cfg(...)` target predicate references a synthetic build flag
/// (`fuzzing`, `test`, `miri`, `clippy`) that is never set for a real target
/// platform in a normal build. Quoted values (e.g. `target_os = "..."`) are
/// ignored so only bare cfg flags are matched.
fn is_synthetic_cfg(target: &str) -> bool {
    let mut unquoted = String::with_capacity(target.len());
    let mut in_quote = false;
    for c in target.chars() {
        match c {
            '"' => in_quote = !in_quote,
            _ if !in_quote => unquoted.push(c),
            _ => {}
        }
    }
    unquoted
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|tok| matches!(tok, "fuzzing" | "test" | "miri" | "clippy"))
}

/// Whether `parent` actually pulls in the dependency crate named `dep_name`
/// given its resolved set of `active` features. A non-optional (non-dev)
/// dependency is always pulled in; an optional one only if some active feature
/// activates it (`name` / `dep:name` / `name/feature`, but not the weak
/// `name?/feature`).
fn dependency_enabled(
    parent: &cargo_metadata::Package,
    active: &HashSet<&str>,
    dep_name: &str,
) -> bool {
    let mut matched = false;
    for dep in &parent.dependencies {
        if dep.kind == cargo_metadata::DependencyKind::Development || dep.name != dep_name {
            continue;
        }
        matched = true;
        if !dep.optional {
            return true;
        }
        // The feature gate uses the dependency's local name (its rename if any).
        let key = dep.rename.as_deref().unwrap_or(&dep.name);
        if active.contains(key) {
            return true;
        }
        let enables =
            |value: &str| value == format!("dep:{key}") || value.starts_with(&format!("{key}/"));
        if active
            .iter()
            .any(|f| parent.features.get(*f).is_some_and(|v| v.iter().any(|x| enables(x))))
        {
            return true;
        }
    }
    // If no matching manifest entry was found (unusual), keep the dependency.
    !matched
}

/// The canonical SPDX string for a requirement, e.g. `MIT` or
/// `LicenseRef-Slint-Software-3.0`.
fn license_string(req: &spdx::LicenseReq) -> String {
    match &req.license {
        spdx::LicenseItem::Spdx { id, .. } => id.name.to_string(),
        spdx::LicenseItem::Other { doc_ref, lic_ref } => match doc_ref {
            Some(doc_ref) => format!("DocumentRef-{doc_ref}:LicenseRef-{lic_ref}"),
            None => format!("LicenseRef-{lic_ref}"),
        },
    }
}

fn license_full_name(req: &spdx::LicenseReq) -> String {
    match &req.license {
        spdx::LicenseItem::Spdx { id, .. } => id.full_name.to_string(),
        spdx::LicenseItem::Other { .. } => license_string(req),
    }
}

/// Collect candidate license files from a crate directory, both the
/// conventional top-level `LICENSE*`/`COPYING*` files and any REUSE-style
/// `LICENSES/<id>.*` files.
fn license_files(dir: &Path) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut collect = |path: &Path| {
        if let (Ok(text), Some(name)) =
            (std::fs::read_to_string(path), path.file_name().and_then(|n| n.to_str()))
        {
            result.push((name.to_string(), text));
        }
    };

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = entry.file_name().to_string_lossy().to_ascii_uppercase();
                if name.starts_with("LICENSE")
                    || name.starts_with("LICENCE")
                    || name.starts_with("COPYING")
                    || name.starts_with("COPYRIGHT")
                    || name.starts_with("UNLICENSE")
                    || name.starts_with("NOTICE")
                {
                    collect(&path);
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(dir.join("LICENSES")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                collect(&path);
            }
        }
    }
    result
}

/// Suffix found on a license file name (after `LICENSE-`/`LICENSE.`) mapped to
/// the SPDX id it most likely refers to.
fn suffix_to_id(suffix: &str) -> Option<&'static str> {
    Some(match suffix.to_ascii_uppercase().as_str() {
        "APACHE" | "APACHE2" | "APACHE-2.0" | "APACHE2.0" => "Apache-2.0",
        "MIT" => "MIT",
        "ZLIB" => "Zlib",
        "MPL" | "MPL-2.0" | "MPL2" => "MPL-2.0",
        "ISC" => "ISC",
        "BSL" | "BOOST" => "BSL-1.0",
        "UNICODE" => "Unicode-3.0",
        _ => return None,
    })
}

/// Find the license text for a given license id among the crate's license
/// files. Matches REUSE files by stem, conventional files by suffix, and falls
/// back to a single generic license file when the crate has only one license.
fn find_license_text(id: &str, files: &[(String, String)]) -> Option<String> {
    // Exact REUSE match: `LICENSES/<id>.txt` or `<id>.md`.
    for (name, text) in files {
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
        if stem.eq_ignore_ascii_case(id) {
            return Some(text.clone());
        }
    }
    // Conventional `LICENSE-<SUFFIX>` / `LICENSE.<SUFFIX>` files.
    for (name, text) in files {
        let upper = name.to_ascii_uppercase();
        let suffix = upper
            .strip_prefix("LICENSE-")
            .or_else(|| upper.strip_prefix("LICENSE."))
            .or_else(|| upper.strip_prefix("LICENCE-"))
            .or_else(|| upper.strip_prefix("LICENCE."));
        if let Some(suffix) = suffix {
            let suffix = suffix.rsplit_once('.').map(|(s, _)| s).unwrap_or(suffix);
            if suffix_to_id(suffix) == Some(id) {
                return Some(text.clone());
            }
        }
    }
    None
}

/// Pick the text shown for a license: the most frequently harvested variant,
/// falling back to the canonical SPDX text when nothing was harvested.
fn representative_text(id: &str, harvested: Option<&HashMap<String, usize>>) -> String {
    if let Some((text, _)) = harvested
        .and_then(|map| map.iter().max_by(|a, b| a.1.cmp(b.1).then(b.0.len().cmp(&a.0.len()))))
    {
        return text.clone();
    }
    spdx::license_id(id)
        .map(|l| l.text().to_string())
        .unwrap_or_else(|| format!("No license text available for {id}."))
}

fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n").trim().to_string()
}

fn crate_url(c: &CrateRef) -> String {
    match &c.repository {
        Some(repo) => repo.clone(),
        None => format!("https://crates.io/crates/{}", c.name),
    }
}

fn render_html(sections: &[LicenseSection]) -> String {
    let mut out = String::new();
    out.push_str(
        r#"<!DOCTYPE html>
<html>
<head>
    <style>
        @media (prefers-color-scheme: dark) {
            body { background: #333; color: white; }
            a { color: skyblue; }
        }
        .container { font-family: sans-serif; max-width: 800px; margin: 0 auto; }
        .intro { text-align: center; }
        .licenses-list { list-style-type: none; margin: 0; padding: 0; }
        .license-used-by { margin-top: -10px; }
        .license-text { max-height: 200px; overflow-y: scroll; white-space: pre-wrap; }
    </style>
</head>
<body>
    <main class="container">
        <div class="intro">
            <p>This program is distributed under the terms outlined in <a href="LICENSE.md">LICENSE.md</a></p>.
            <h1>Third Party Licenses</h1>
            <p>This page lists the licenses of the dependencies used by this program.</p>
        </div>

        <h2>Overview of licenses:</h2>
        <ul class="licenses-overview">
"#,
    );
    for s in sections {
        out.push_str(&format!(
            "            <li><a href=\"#{id}\">{name}</a> ({count})</li>\n",
            id = html_escape(&s.id),
            name = html_escape(&s.name),
            count = s.count
        ));
    }
    out.push_str("        </ul>\n\n        <h2>All license text:</h2>\n        <ul class=\"licenses-list\">\n");
    for s in sections {
        out.push_str("            <li class=\"license\">\n");
        out.push_str(&format!(
            "                <h3 id=\"{id}\">{name}</h3>\n",
            id = html_escape(&s.id),
            name = html_escape(&s.name)
        ));
        out.push_str(
            "                <h4>Used by:</h4>\n                <ul class=\"license-used-by\">\n",
        );
        for c in &s.used_by {
            out.push_str(&format!(
                "                    <li><a href=\"{url}\">{name} {version}</a></li>\n",
                url = html_escape(&crate_url(c)),
                name = html_escape(&c.name),
                version = html_escape(&c.version)
            ));
        }
        out.push_str("                </ul>\n");
        out.push_str(&format!(
            "                <pre class=\"license-text\">{text}</pre>\n",
            text = html_escape(&s.text)
        ));
        out.push_str("            </li>\n");
    }
    out.push_str("        </ul>\n    <main></body></html>\n");
    out
}

/// Emit a subset of `cargo about`'s JSON output. The docs site generators
/// (`docs/common/src/utils/thirdparty.ts`) consume `licenses[].{name,id,text}`
/// and `licenses[].used_by[].crate.{name,version,repository}`.
fn render_json(sections: &[LicenseSection]) -> String {
    use serde_json::json;
    let overview: Vec<_> =
        sections.iter().map(|s| json!({ "name": s.name, "id": s.id, "count": s.count })).collect();
    let licenses: Vec<_> = sections
        .iter()
        .map(|s| {
            let used_by: Vec<_> = s
                .used_by
                .iter()
                .map(|c| {
                    json!({ "crate": {
                        "name": c.name,
                        "version": c.version,
                        "repository": c.repository,
                    }})
                })
                .collect();
            json!({ "name": s.name, "id": s.id, "text": s.text, "used_by": used_by })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "overview": overview, "licenses": licenses }))
        .expect("serializable")
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}
