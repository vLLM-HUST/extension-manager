import pytest

from vllmhust.manifest import ManifestError, parse_manifest


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "bundle_id": "org.vllm-hust.example",
        "bundle_version": "1.2.3",
        "host_api_range": ">=1,<2",
        "components": [
            {
                "component_id": "scheduler",
                "contracts": ["vllm.scheduler.policy.v1"],
                "execution_planes": ["scheduler"],
                "isolation": "trusted_in_process",
                "implementation_ref": "example.plugin:Scheduler",
                "permissions": [],
            }
        ],
    }


def test_manifest_accepts_bidkv_shape() -> None:
    manifest = parse_manifest(valid_manifest())
    assert manifest.bundle_id == "org.vllm-hust.example"
    assert manifest.components[0].component_id == "scheduler"


def test_manifest_rejects_unknown_field() -> None:
    payload = valid_manifest()
    payload["surprise"] = True
    with pytest.raises(ManifestError, match="unknown fields"):
        parse_manifest(payload)


def test_manifest_rejects_incompatible_host_api() -> None:
    payload = valid_manifest()
    payload["host_api_range"] = ">=2"
    with pytest.raises(ManifestError, match="host provides"):
        parse_manifest(payload)
