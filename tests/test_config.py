from pathlib import Path

from vllm_hust_ext.config import (
    ExtensionConfig,
    UserConfig,
    load_config,
    save_config,
)


def test_config_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    expected = UserConfig(
        {"org.vllm-hust.bidkv": ExtensionConfig(True, {"utility_strategy": "bidkv"})}
    )
    save_config(expected, path)
    assert load_config(path) == expected


def test_missing_config_is_empty(tmp_path: Path) -> None:
    assert load_config(tmp_path / "missing.json") == UserConfig()


def test_schema_v1_enablement_is_migrated_in_memory(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        '{"schema_version":1,"enabled":["org.vllm-hust.bidkv"]}',
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.extension("org.vllm-hust.bidkv").enabled is True


def test_without_extension_removes_stored_intent() -> None:
    config = UserConfig(
        {
            "org.vllm-hust.bidkv": ExtensionConfig(
                True, {"victim_selector_plugin": "bidkv"}
            )
        }
    )

    forgotten = config.without_extension("org.vllm-hust.bidkv")

    assert forgotten.extensions == {}
    assert config.extension("org.vllm-hust.bidkv").enabled is True
