from pathlib import Path

from vllm_hust_ext.config import UserConfig, load_config, save_config


def test_config_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    expected = UserConfig(("org.vllm-hust.bidkv",))
    save_config(expected, path)
    assert load_config(path) == expected


def test_missing_config_is_empty(tmp_path: Path) -> None:
    assert load_config(tmp_path / "missing.json") == UserConfig()
