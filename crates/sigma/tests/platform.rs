//! `SigmaEngine::load_dir_for` (#980): a host loads only the rules of its own platform, and
//! the platform is where a rule sits **under the rules directory**, never a word in the
//! path of the content root.

use std::path::{Path, PathBuf};

use schema::{EventMeta, ExecEvent};
use sigma::{Platform, SigmaEngine};

const ALL: [Platform; 3] = [Platform::Linux, Platform::Windows, Platform::MacOs];

fn rule(title: &str) -> String {
    format!(
        "title: {title}\ndescription: d\ntags:\n  - attack.t1059\nlevel: low\nfalsepositives:\n  - none\n\
         detection:\n  selection:\n    Image|endswith: '/x'\n  condition: selection\n"
    )
}

fn write(root: &Path, relative: &str, title: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, rule(title)).unwrap();
}

/// A rules directory with one rule per platform, each titled after it.
fn tree(root: &Path) {
    write(root, "linux/a.yml", "linux-rule");
    write(root, "windows/a.yml", "windows-rule");
    write(root, "macos/a.yml", "macos-rule");
}

fn titles(engine: &SigmaEngine) -> Vec<String> {
    let mut titles: Vec<String> = engine
        .rule_titles()
        .iter()
        .map(ToString::to_string)
        .collect();
    titles.sort();
    titles
}

#[test]
fn each_platform_loads_only_its_own_directory() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    for (platform, title) in [
        (Platform::Linux, "linux-rule"),
        (Platform::Windows, "windows-rule"),
        (Platform::MacOs, "macos-rule"),
    ] {
        let engine = SigmaEngine::load_dir_for(dir.path(), platform).unwrap();
        assert_eq!(titles(&engine), [title], "{platform:?}");
    }
}

#[test]
fn a_platform_word_in_the_content_root_does_not_change_a_rules_platform() {
    // The root itself is called `linux` and `windows`: judged from the full path, every rule
    // under it would look like both.
    let dir = tempfile::tempdir().unwrap();
    let root = dir
        .path()
        .join("linux")
        .join("windows")
        .join("content")
        .join("rules")
        .join("sigma");
    tree(&root);
    for (platform, title) in [
        (Platform::Linux, "linux-rule"),
        (Platform::Windows, "windows-rule"),
        (Platform::MacOs, "macos-rule"),
    ] {
        let engine = SigmaEngine::load_dir_for(&root, platform).unwrap();
        assert_eq!(titles(&engine), [title], "{platform:?}");
    }
}

#[test]
fn rules_nested_below_the_platform_directory_load() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/sub/deeper/a.yml", "nested");
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::Linux).unwrap();
    assert_eq!(titles(&engine), ["nested"]);
    let other = SigmaEngine::load_dir_for(dir.path(), Platform::Windows).unwrap();
    assert_eq!(other.rule_count(), 0);
}

#[test]
fn a_rule_outside_a_platform_directory_is_loaded_for_no_platform() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    write(dir.path(), "other/a.yml", "other-rule");
    write(dir.path(), "top-level.yml", "top-rule");
    for platform in ALL {
        let engine = SigmaEngine::load_dir_for(dir.path(), platform).unwrap();
        let loaded = titles(&engine);
        assert!(
            !loaded.iter().any(|t| t == "other-rule" || t == "top-rule"),
            "{platform:?}: {loaded:?}"
        );
    }
}

#[test]
fn a_platform_directory_that_does_not_exist_gives_an_engine_with_no_rules() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/a.yml", "linux-rule");
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::MacOs).unwrap();
    assert_eq!(engine.rule_count(), 0);
}

#[test]
fn a_rules_directory_that_cannot_be_read_is_an_error_even_without_the_platform_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nowhere");
    assert!(SigmaEngine::load_dir_for(&missing, Platform::Linux).is_err());
}

#[test]
fn a_rule_that_does_not_validate_is_skipped_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "linux/good.yml", "good");
    std::fs::write(dir.path().join("linux/bad.yml"), "title: [unterminated").unwrap();
    let engine = SigmaEngine::load_dir_for(dir.path(), Platform::Linux).unwrap();
    assert_eq!(titles(&engine), ["good"]);
}

#[test]
fn load_dir_is_unchanged_and_still_loads_every_platform() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let engine = SigmaEngine::load_dir(dir.path()).unwrap();
    assert_eq!(
        titles(&engine),
        ["linux-rule", "macos-rule", "windows-rule"]
    );
}

#[test]
fn the_host_platform_is_known_on_the_systems_the_content_covers() {
    let host = Platform::host();
    #[cfg(target_os = "linux")]
    assert_eq!(host, Some(Platform::Linux));
    #[cfg(target_os = "windows")]
    assert_eq!(host, Some(Platform::Windows));
    #[cfg(target_os = "macos")]
    assert_eq!(host, Some(Platform::MacOs));
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    assert_eq!(host, None);
    assert_eq!(Platform::Linux.dir_name(), "linux");
    assert_eq!(Platform::Windows.dir_name(), "windows");
    assert_eq!(Platform::MacOs.dir_name(), "macos");
}

// ── the shipped content ──────────────────────────────────────────────────────

fn content_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigma")
}

fn rule_files(dir: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "yml") {
                count += 1;
            }
        }
    }
    count
}

#[test]
fn the_shipped_content_splits_exactly_by_platform() {
    let all = SigmaEngine::load_dir(&content_dir()).unwrap().rule_count();
    let mut sum = 0;
    for platform in ALL {
        let engine = SigmaEngine::load_dir_for(&content_dir(), platform).unwrap();
        let on_disk = rule_files(&content_dir().join(platform.dir_name()));
        assert!(on_disk > 0, "{platform:?} ships no rules");
        assert_eq!(engine.rule_count(), on_disk, "{platform:?}");
        sum += engine.rule_count();
    }
    assert_eq!(
        sum, all,
        "every shipped rule belongs to exactly one platform"
    );
}

fn exec(parent: &str, image: &str) -> ExecEvent {
    ExecEvent {
        meta: EventMeta {
            pid: 1,
            comm: "test".into(),
            ..schema::fixtures::meta()
        },
        image_path: image.into(),
        cmdline: "sh -c id".into(),
        parent_image_path: Some(parent.into()),
        ..schema::fixtures::exec()
    }
}

#[test]
fn the_macos_web_server_rule_does_not_fire_on_a_linux_host() {
    const MACOS_RULE: &str = "Web server spawned a shell on macOS";
    let event = exec("/usr/sbin/nginx", "/bin/sh");
    let fires = |platform| {
        SigmaEngine::load_dir_for(&content_dir(), platform)
            .unwrap()
            .eval_exec(&event)
            .iter()
            .any(|a| a.title == MACOS_RULE)
    };
    assert!(fires(Platform::MacOs), "it must still fire on macOS");
    assert!(!fires(Platform::Linux), "the Linux host must not run it");
    assert!(!fires(Platform::Windows));
    // The full-tree loader still runs it everywhere, as before.
    let everywhere = SigmaEngine::load_dir(&content_dir()).unwrap();
    assert!(
        everywhere
            .eval_exec(&event)
            .iter()
            .any(|a| a.title == MACOS_RULE)
    );
}
