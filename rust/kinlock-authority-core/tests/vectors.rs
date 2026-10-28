//! Every conformance vector Python wrote must come out byte for byte the same here.

use std::fs;
use std::path::PathBuf;

use kinlock_authority_core::canonical::canonical;
use kinlock_authority_core::conformance::run;
use serde_json::{Map, Value};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors")
}

fn resolve(input: &Value, fixtures: &Map<String, Value>) -> Value {
    match input {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| {
                    let v = match v.as_str().and_then(|s| s.strip_prefix('@')) {
                        Some(name) => fixtures
                            .get(name)
                            .cloned()
                            .unwrap_or_else(|| panic!("unknown fixture {name}")),
                        None => v.clone(),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[test]
fn all_vectors_match_python() {
    let fixtures: Value = serde_json::from_str(
        &fs::read_to_string(dir().join("fixtures.json")).expect("fixtures.json"),
    )
    .expect("fixtures parse");
    let fixtures = fixtures.as_object().expect("fixtures object");
    let mut paths: Vec<PathBuf> = fs::read_dir(dir())
        .expect("vectors dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json") && !p.ends_with("fixtures.json"))
        .collect();
    paths.sort();
    let (mut total, mut failed) = (0usize, Vec::new());
    for path in &paths {
        let suite: Value =
            serde_json::from_str(&fs::read_to_string(path).expect("read")).expect("parse");
        let op = suite["op"].as_str().expect("op");
        for case in suite["cases"].as_array().expect("cases") {
            total += 1;
            let got = run(op, &resolve(&case["input"], fixtures));
            let (g, e) = (canonical(&got), canonical(&case["expected"]));
            if g != e {
                failed.push(format!(
                    "{op} {}\n  expected {e}\n  got      {g}",
                    case.get("name").map(|n| n.to_string()).unwrap_or_default()
                ));
            }
        }
    }
    println!("{} of {total} vectors match", total - failed.len());
    assert!(total > 5000, "only {total} vectors found");
    assert!(
        failed.is_empty(),
        "{} of {total} vectors differ:\n{}",
        failed.len(),
        failed
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
