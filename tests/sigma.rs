use std::path::Path;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value as Json;

fn hunt_json(root: &Path, preprocess: bool) -> Vec<Json> {
    let mut cmd = cargo_bin_cmd!("chainsaw");
    cmd.arg("--no-banner")
        .arg("hunt")
        .arg(root.join("events.json"))
        .arg("-s")
        .arg(root.join("rules"))
        .arg("-m")
        .arg(root.join("mapping.yml"))
        .arg("--json")
        .arg("-q");
    if preprocess {
        cmd.arg("--preprocess");
    }

    let output = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&output).expect("failed to parse chainsaw JSON output")
}

#[test]
fn sigma_correlation_outputs_all_events_and_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sigma/correlation");
    for preprocess in [false, true] {
        let detections = hunt_json(&root, preprocess);
        let correlation = detections
            .iter()
            .find(|detection| detection["name"] == "Repeated Failed Logons")
            .expect("correlation detection was not emitted");

        assert_eq!(correlation["kind"], "aggregate");
        assert_eq!(
            correlation["documents"]
                .as_array()
                .expect("missing correlation documents")
                .len(),
            2
        );
        assert_eq!(
            correlation["context"]
                .as_array()
                .expect("missing correlation context")
                .len(),
            2
        );
        assert_eq!(correlation["correlation"]["type"], "event_count");
    }
}

#[test]
fn sigma_field_modifiers_are_evaluated() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sigma/modifiers");
    for preprocess in [false, true] {
        let detections = hunt_json(&root, preprocess);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0]["name"], "Modifier Match");
        assert_eq!(detections[0]["context"]["Source IP"], "10.1.2.3");
    }
}
