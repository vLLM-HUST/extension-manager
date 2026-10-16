"""New long-prompt KV cohort; actual tokenizer freeze, finite metadata scope only."""

from __future__ import annotations

import argparse
import importlib.metadata
import inspect
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .request_runner import (
    CLASSIFICATION,
    canonical,
    make_recipe,
    require,
    sha,
    validate_rpc_budget,
)

SCHEMA = "ecpa-native-kv-challenge-campaign/v1"
SCHEMA_V2 = "ecpa-native-kv-challenge-campaign/v2"
REQUIREMENTS = {
    "attention_group": 0,
    "semantic_anchor": 1201,
    "physical_anchor": 1024,
    "compression_threshold_tokens": 1152,
    "allocation_block_size": 128,
    "destination_block_count": 8,
}


HOST47_VERSION = "0.31.1.post1.dev5+g47c8aa1ca.empty"
HOST47_PROFILE = "vllm-hust-main-47c8aa1-tokenization/v1"
HOST47_REVISION = "47c8aa1caa7638d2e5e231eedced45448106fde5"
# Exact installed main47c source bytes, already matched to its genuine wheel.
HOST47_TOKENIZATION_SOURCES = dict(
    [
        (
            "vllm/entrypoints/openai/chat_completion/serving.py",
            "dabae194cfc044ff6613081a0f037e5c6d4739ebc97abf553291ffe019a614ae",
        ),
        (
            "vllm/entrypoints/serve/engine/serving.py",
            "e46693a37e9a8b1087c8cee8a1e2cb9a2ce3d052772e3771755ef59de0885cf4",
        ),
        (
            "vllm/renderers/base.py",
            "0c3bd445c5850c05322ac8a761b1a4248ee818a30fd4ea14c1d3151e388dfefc",
        ),
        (
            "vllm/renderers/chat_utils/__init__.py",
            "8845f7a5e1e3b5d143e332c47080b21b766f1c75bc7f66d9569ed3fe74a108c3",
        ),
        (
            "vllm/renderers/chat_utils/chat_message.py",
            "485f5a8ec0bd4d6851759540eb36dfa4fc5668336ff1226f58575bf1329617a1",
        ),
        (
            "vllm/renderers/chat_utils/chat_template.py",
            "4902877fd1c02cca35dca00c2c9d6b1a41681736ebb054e4a83551cecd252884",
        ),
        (
            "vllm/renderers/chat_utils/content_parser.py",
            "e86b0f673ed04ef6c00f0ca9a49e4288aed78a206ebaae15fece1a85b6feb2c7",
        ),
        (
            "vllm/renderers/chat_utils/item_tracker.py",
            "b69d27d47b701071680af9af7e3540fa18aba1f3551c10e3343e1cfc97a7615d",
        ),
        (
            "vllm/renderers/chat_utils/tool_call.py",
            "ba40d87fe363eea14427eb3c5abbb81d8b1bdd501b5abc800d6fff3cc9ea5611",
        ),
        (
            "vllm/renderers/chat_utils/types.py",
            "b09b8cfdc1d77b1428e7700634dffd4ec3c0c49667a25dc93f0bc93b6316a16a",
        ),
        (
            "vllm/renderers/hf.py",
            "1302669451e8a4af91aa5248501723e7f8045a2acb5e05b70651b331ad102895",
        ),
        (
            "vllm/renderers/inputs/__init__.py",
            "2d7ea91cbfa17ecc73abe425d7a73a77a568f064f09d026989bc5fa8f601a379",
        ),
        (
            "vllm/renderers/inputs/preprocess.py",
            "7890fa28f8594107fb2ff2c61e07ea045912e423d47111254bbccd381034b813",
        ),
        (
            "vllm/renderers/inputs/tokenize.py",
            "c8a9e19972a8106b6bd84715fdbdf54d9219502baba32a06e803ff4fda2dff5d",
        ),
        (
            "vllm/renderers/online_renderer.py",
            "a8f90b4d1d41b2194557992a12105f65bf720d743384e18ee01c2870a75a7c72",
        ),
        (
            "vllm/renderers/params.py",
            "5113461cd308266727d9ced82900cbe65ae50245a2f3cb16224f6689574570a9",
        ),
        (
            "vllm/renderers/registry.py",
            "5ea03ecad81f8911c72112656f2456c05e0e57122be99af05c27464466596844",
        ),
        (
            "vllm/tokenizers/__init__.py",
            "29548902d92ec30fbed3cbf3f76225d9766a18dae9ef54553eb48284e4dbf653",
        ),
        (
            "vllm/tokenizers/hf.py",
            "4c2712de92e8fec91b9d7f3b5b162bd1f0683e7fc21c16b20188a505fc6c6fea",
        ),
        (
            "vllm/tokenizers/protocol.py",
            "15ec34808171509114ce97dd1fa903475ce2e4699a862321e3f59c075518573c",
        ),
        (
            "vllm/tokenizers/registry.py",
            "57fce5fb82a1585f2571a84448bc7e354e36825863b6cc07ece3845b8398a9d4",
        ),
        (
            "vllm/v1/engine/input_processor.py",
            "960d57f5a91b6856f64f13a1bae1444c58b2226a5f976ad7a264517368d6d8e7",
        ),
    ]
)


STRICT_COPY = "strict-system-copy-v1"
STRICT_SYSTEM = (
    "You are a deterministic text-copying assistant. Copy the entire text inside "
    "<answer>...</answer> in the user message exactly. Output only that text, "
    "preserving its single space. Do not explain, summarize, add labels, or stop "
    "after its first part."
)


def strict_copy_messages(expected, padding):
    require(type(padding) is int and 0 <= padding < 2402, "strict padding invalid")
    return [
        {"role": "system", "content": STRICT_SYSTEM},
        {
            "role": "user",
            "content": (
                "Ignore this padding:\n"
                + "pad " * padding
                + "\nCopy both space-separated strings below, verbatim. Your complete "
                "reply must contain both strings and nothing else.\n<answer>"
                + expected
                + "</answer>\nReturn the entire contents of <answer> exactly, "
                "including both strings separated by one space."
            ),
        },
    ]


def actual_chat_ids(tokenizer, messages):
    ids = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        return_dict=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    require(
        isinstance(ids, list) and all(type(x) is int and x >= 0 for x in ids),
        "actual tokenizer did not return plain token IDs",
    )
    return ids


def runtime_tokenization_binding(tokenizer):
    method_path = Path(
        inspect.getsourcefile(type(tokenizer).apply_chat_template)
    ).resolve()
    implementation = {"path": str(method_path), "sha256": sha(method_path.read_bytes())}
    fixture = type(tokenizer).__name__ == "CPUFixtureTokenizer"
    if fixture:
        return {
            "classification": "CPU_TOKENIZER_FIXTURE_ONLY",
            "transformers_version": None,
            "host_version": None,
            "implementation_source": implementation,
            "host_sources": [],
        }
    host = importlib.metadata.distribution("vllm")
    host_paths = [
        "vllm/renderers/hf.py",
        "vllm/renderers/chat_utils.py",
        "vllm/renderers/base.py",
        "vllm/renderers/params.py",
        "vllm/tokenizers/hf.py",
        "vllm/entrypoints/openai/chat_completion/serving.py",
        "vllm/entrypoints/serve/engine/serving.py",
        "vllm/v1/engine/input_processor.py",
    ]
    new_profile = host.version == HOST47_VERSION
    if new_profile:
        host_paths = list(HOST47_TOKENIZATION_SOURCES)
    sources = []
    for relative in host_paths:
        path = Path(host.locate_file(relative)).resolve()
        require(path.is_file(), "actual Host tokenization source is unavailable")
        digest = sha(path.read_bytes())
        if new_profile:
            require(
                digest == HOST47_TOKENIZATION_SOURCES[relative],
                "main47c tokenization module bytes differ",
            )
        sources.append(
            {
                "path": str(path),
                "sha256": digest,
                **({"relative_path": relative} if new_profile else {}),
            }
        )
    return {
        "classification": "ACTUAL_LOCAL_TOKENIZER_CPU_PREFLIGHT_ONLY",
        "transformers_version": importlib.metadata.version("transformers"),
        "host_version": host.version,
        "implementation_source": implementation,
        "host_sources": sources,
        **(
            {
                "host_tokenization_profile": HOST47_PROFILE,
                "host_revision": HOST47_REVISION,
            }
            if new_profile
            else {}
        ),
    }


def make_kv_recipe(
    phase_targets,
    sources,
    tokenizer,
    tokenizer_sources,
    *,
    materialized_row=False,
    rpc_budget_s=None,
    prompt_variant=None,
    ack_time_policy=None,
):
    """No guessed prompt length: fail if actual local template cannot reach 1201."""
    from .kv_time_policy import FINAL_PREFIX_POLICY

    require(
        ack_time_policy in (None, FINAL_PREFIX_POLICY), "unknown KV ACK time policy"
    )
    if ack_time_policy is not None:
        require(
            materialized_row and rpc_budget_s == 180,
            "final-prefix policy requires KV v2 budget180",
        )
    require(prompt_variant in (None, STRICT_COPY), "unknown KV prompt variant")
    if prompt_variant is not None:
        require(materialized_row, "strict prompt requires opt-in KV v2")
        require(rpc_budget_s == 180, "strict copy requires frozen RPC budget180")
    if rpc_budget_s is not None:
        require(materialized_row, "frozen RPC budget requires opt-in KV v2")
        validate_rpc_budget(rpc_budget_s)
    recipe = make_recipe(phase_targets, sources)
    recipe["schema"] = SCHEMA_V2 if materialized_row else SCHEMA
    recipe["request_scope"] = "KV-host-metadata-to-later-upload-only"
    if ack_time_policy is not None:
        from . import collector_client, kv_time_policy

        for module in (collector_client, kv_time_policy):
            path = Path(module.__file__).resolve()
            if not any(x["path"] == str(path) for x in recipe["sources"]):
                recipe["sources"].append(
                    {"path": str(path), "sha256": sha(path.read_bytes())}
                )
    require(tokenizer_sources, "tokenizer source bytes required")
    runtime_binding = runtime_tokenization_binding(tokenizer)
    for phase in recipe["phases"]:
        if ack_time_policy is not None:
            phase["ack_time_policy"] = ack_time_policy
            phase["ack_client_source_sha256"] = sha(
                Path(collector_client.__file__).read_bytes()
            )
        if rpc_budget_s is not None:
            phase["rpc_budget_s"] = rpc_budget_s
        expected = ("ECPA-CHALLENGE-" + phase["challenge_nonce"] + " ") * 2
        expected = expected.strip()
        if prompt_variant == STRICT_COPY:
            expected_ids = tokenizer.encode(expected, add_special_tokens=False)
            require(
                isinstance(expected_ids, list)
                and all(type(x) is int and x >= 0 for x in expected_ids)
                and 32 <= len(expected_ids) <= 128,
                "single-sampled strict oracle cannot satisfy frozen decode bounds",
            )
            phase["prompt_variant"] = STRICT_COPY
            phase["oracle_tokenization"] = {
                "schema": "ecpa-strict-copy-oracle-tokenization/v1",
                "token_ids": expected_ids,
                "token_ids_sha256": sha(canonical(expected_ids)),
                "count": len(expected_ids),
                "add_special_tokens": False,
                "sample_policy": (
                    "one-fresh-nonce-cpu-reject-if-short-no-runtime-retuning"
                ),
            }
        selected = None
        for padding in range(2402):
            content = (
                "Read the padding silently:\n"
                + "pad " * padding
                + "\nReply exactly: "
                + expected
            )
            messages = (
                strict_copy_messages(expected, padding)
                if prompt_variant == STRICT_COPY
                else [{"role": "user", "content": content}]
            )
            ids = actual_chat_ids(tokenizer, messages)
            if len(ids) == 1201:
                selected = messages, ids
                if prompt_variant == STRICT_COPY:
                    phase["padding_count"] = padding
                break
        require(
            selected is not None, "actual tokenizer cannot freeze exact 1201 prompt"
        )
        messages, ids = selected
        phase["payload"].update(
            messages=messages,
            max_tokens=128,
            chat_template_kwargs={"enable_thinking": False},
        )
        phase["response_oracle"]["expected"] = expected
        phase["kv_requirements"] = dict(REQUIREMENTS)
        phase["minimum_completion_tokens"] = 32
        phase["tokenization"] = {
            "schema": "ecpa-actual-KV-chat-tokenization/v1",
            "tokenizer_class": type(tokenizer).__name__,
            "runtime_binding": runtime_binding,
            "assets": tokenizer_sources,
            "messages_sha256": sha(canonical(messages)),
            "template_kwargs": {"enable_thinking": False},
            "add_generation_prompt": True,
            "prompt_token_ids": ids,
            "prompt_token_ids_sha256": sha(canonical(ids)),
            "prompt_token_count": len(ids),
        }
    validate_kv(recipe)
    return recipe


def validate_kv(recipe, *, source_resolver=None):
    return validate_kv_fields(
        recipe,
        supported_schemas={SCHEMA, SCHEMA_V2},
        materialized_schema=SCHEMA_V2,
        source_resolver=source_resolver,
    )


def validate_kv_fields(
    recipe,
    *,
    supported_schemas,
    materialized_schema,
    ack_client_source=None,
    source_resolver=None,
):
    """Shared complete request/tokenizer predicates, with explicit protocol inputs.

    This field validator never issues native qualification. New typed protocols
    must pin their own real ACK client; the legacy wrapper retains its defaults.
    """
    require(
        recipe["schema"] in supported_schemas
        and recipe["classification"] == CLASSIFICATION
        and recipe["formal_result"] is False
        and recipe["native_ids_preregistered_before_launch"] is False
        and recipe["request_scope"] == "KV-host-metadata-to-later-upload-only",
        "KV cohort scope changed",
    )
    require(
        all(
            recipe[k] is None
            for k in ["lost_requests", "duplicate_requests", "full_objective_satisfied"]
        ),
        "KV unknown objective promoted",
    )
    require(
        recipe["sources"] and 0 < len(recipe["phases"]) <= 64,
        "bounded source-pinned KV cohort required",
    )
    resolve = source_resolver or Path
    for source in recipe["sources"]:
        path = resolve(source["path"])
        require(
            path.is_absolute()
            and path.is_file()
            and sha(path.read_bytes()) == source["sha256"],
            "KV frozen source changed",
        )
    for key in [
        "phase_id",
        "client_request_id",
        "challenge_nonce",
        "expected_response_id",
    ]:
        require(
            len({p[key] for p in recipe["phases"]}) == len(recipe["phases"]),
            "KV phase/request/nonce reused",
        )
    from .kv_time_policy import FINAL_PREFIX_POLICY

    for phase in recipe["phases"]:
        policy = phase.get("ack_time_policy")
        require(policy in (None, FINAL_PREFIX_POLICY), "unknown KV ACK time policy")
        if policy is not None:
            require(
                recipe["schema"] == materialized_schema
                and phase.get("rpc_budget_s") == 180,
                "final-prefix policy requires frozen KV v2 budget180",
            )
            basename, expected_digest = (
                ("collector_client.py", phase["ack_client_source_sha256"])
                if ack_client_source is None
                else ack_client_source
            )
            require(
                phase["ack_client_source_sha256"] == expected_digest
                and any(
                    x["path"].endswith("/" + basename)
                    and x["sha256"] == expected_digest
                    for x in recipe["sources"]
                ),
                "ACK client source is not frozen",
            )
        else:
            require(
                "ack_client_source_sha256" not in phase,
                "ACK policy source without policy",
            )
        variant = phase.get("prompt_variant")
        require(variant in (None, STRICT_COPY), "unknown KV prompt variant")
        if variant is not None:
            require(
                recipe["schema"] == materialized_schema,
                "strict prompt requires opt-in KV v2",
            )
            require(phase.get("rpc_budget_s") == 180, "strict copy RPC budget changed")
        if "rpc_budget_s" in phase:
            require(
                recipe["schema"] == materialized_schema,
                "frozen RPC budget requires opt-in KV v2",
            )
            validate_rpc_budget(phase["rpc_budget_s"])
        client, nonce = phase["client_request_id"], phase["challenge_nonce"]
        require(
            re.fullmatch(r"[a-zA-Z0-9._-]{1,80}", phase["phase_id"]) is not None
            and all(
                re.fullmatch(r"[0-9a-f]{32}", x) is not None for x in [client, nonce]
            ),
            "KV phase/client nonce invalid",
        )
        url = urlsplit(phase["url"])
        require(
            url.scheme == "http"
            and url.hostname == "127.0.0.1"
            and url.port is not None
            and url.path == "/v1/chat/completions"
            and not url.query
            and not url.fragment
            and url.username is None,
            "direct KV endpoint required",
        )
        require(
            phase["expected_ranks"] == [0, 1]
            and phase["external_request_id"]
            == phase["expected_response_id"]
            == "chatcmpl-" + client,
            "KV native external request binding changed",
        )
        require(
            phase["headers"]
            == {"Content-Type": "application/json", "X-Request-Id": client},
            "KV HTTP identity changed",
        )
        payload, tokenization = phase["payload"], phase["tokenization"]
        require(
            payload["request_id"] == client
            and payload["temperature"] == 0
            and payload["n"] == 1
            and payload["stream"] is False
            and payload["max_tokens"] == 128
            and payload["chat_template_kwargs"] == {"enable_thinking": False},
            "KV bounded decode policy changed",
        )
        require(
            phase["minimum_completion_tokens"] == 32
            and phase["kv_requirements"] == REQUIREMENTS,
            "KV frozen semantic/decode predicate changed",
        )
        expected = " ".join(["ECPA-CHALLENGE-" + nonce] * 2)
        require(
            phase["response_oracle"]
            == {
                "expected": expected,
                "strip_outer_whitespace": True,
                "finish_reason": "stop",
            },
            "KV nonce response oracle changed",
        )
        messages = payload["messages"]
        if variant == STRICT_COPY:
            require(
                messages == strict_copy_messages(expected, phase.get("padding_count")),
                "strict canonical two-message prompt changed",
            )
            require(
                set(payload)
                == {
                    "request_id",
                    "model",
                    "messages",
                    "temperature",
                    "max_tokens",
                    "n",
                    "stream",
                    "chat_template_kwargs",
                },
                "strict copy forbids extra decode constraints",
            )
            receipt = phase["oracle_tokenization"]
            expected_ids = receipt["token_ids"]
            require(
                set(receipt)
                == {
                    "schema",
                    "token_ids",
                    "token_ids_sha256",
                    "count",
                    "add_special_tokens",
                    "sample_policy",
                }
                and receipt["schema"] == "ecpa-strict-copy-oracle-tokenization/v1"
                and isinstance(expected_ids, list)
                and all(type(x) is int and x >= 0 for x in expected_ids)
                and 32 <= receipt["count"] == len(expected_ids) <= 128
                and receipt["token_ids_sha256"] == sha(canonical(expected_ids))
                and receipt["add_special_tokens"] is False
                and receipt["sample_policy"]
                == "one-fresh-nonce-cpu-reject-if-short-no-runtime-retuning",
                "strict single-sampled oracle tokenizer receipt changed",
            )
        else:
            require(
                isinstance(messages, list)
                and len(messages) == 1
                and set(messages[0]) == {"role", "content"}
                and messages[0]["role"] == "user"
                and messages[0]["content"].endswith("\nReply exactly: " + expected),
                "KV challenge prompt changed",
            )
        ids = tokenization["prompt_token_ids"]
        require(
            tokenization["schema"] == "ecpa-actual-KV-chat-tokenization/v1"
            and tokenization["assets"]
            and tokenization["tokenizer_class"]
            and tokenization["messages_sha256"] == sha(canonical(messages))
            and tokenization["template_kwargs"] == {"enable_thinking": False}
            and tokenization["add_generation_prompt"] is True
            and tokenization["prompt_token_count"] == len(ids) == 1201
            and all(type(x) is int and x >= 0 for x in ids)
            and tokenization["prompt_token_ids_sha256"] == sha(canonical(ids)),
            "KV actual tokenizer receipt changed",
        )
        binding = tokenization["runtime_binding"]
        require(
            binding["classification"]
            in {
                "CPU_TOKENIZER_FIXTURE_ONLY",
                "ACTUAL_LOCAL_TOKENIZER_CPU_PREFLIGHT_ONLY",
            },
            "tokenization source classification unsupported",
        )
        if binding["classification"] != "CPU_TOKENIZER_FIXTURE_ONLY":
            profile = binding.get("host_tokenization_profile")
            require(
                profile in (None, HOST47_PROFILE), "unknown Host tokenization profile"
            )
            if profile is None:
                require(
                    binding["host_version"] != HOST47_VERSION,
                    "main47c tokenization profile/version/source binding differs",
                )
                require(
                    len(binding["host_sources"]) == 8,
                    "legacy Host tokenization source binding incomplete",
                )
            else:
                require(
                    binding["host_version"] == HOST47_VERSION
                    and binding.get("host_revision") == HOST47_REVISION
                    and len(binding["host_sources"]) == len(HOST47_TOKENIZATION_SOURCES)
                    and {
                        x.get("relative_path"): x["sha256"]
                        for x in binding["host_sources"]
                    }
                    == HOST47_TOKENIZATION_SOURCES,
                    "main47c tokenization profile/version/source binding differs",
                )
                for source in binding["host_sources"]:
                    require(
                        Path(source["path"])
                        .as_posix()
                        .endswith("/" + source["relative_path"]),
                        "main47c source module path differs",
                    )
            require(
                binding["transformers_version"] and binding["host_version"],
                "actual Host/transformers tokenization source binding incomplete",
            )
        for binding_source in [
            binding["implementation_source"],
            *binding["host_sources"],
        ]:
            path = resolve(binding_source["path"])
            require(
                path.is_absolute()
                and path.is_file()
                and sha(path.read_bytes()) == binding_source["sha256"],
                "tokenization implementation source bytes changed",
            )
        for asset in tokenization["assets"]:
            path = resolve(asset["path"])
            require(
                path.is_absolute()
                and path.is_file()
                and sha(path.read_bytes()) == asset["sha256"],
                "KV tokenizer assets changed",
            )
        require(
            not any(
                k in phase
                for k in ["native_plan_id", "native_launch_id", "runtime_request_id"]
            ),
            "KV native identities must be minted after launch",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--model-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--materialized-row-v2", action="store_true")
    parser.add_argument("--rpc-budget-s", type=float)
    parser.add_argument("--prompt-variant", choices=[STRICT_COPY])
    from .kv_time_policy import FINAL_PREFIX_POLICY

    parser.add_argument("--ack-time-policy", choices=[FINAL_PREFIX_POLICY])
    args = parser.parse_args()
    from transformers import AutoTokenizer

    config = json.loads(args.configuration.read_bytes())
    directory = args.model_directory.resolve(strict=True)
    assets = [
        {"path": str(p), "sha256": sha(p.read_bytes())}
        for p in sorted(directory.iterdir())
        if p.is_file()
        and p.suffix in {".json", ".txt", ".jinja", ".model", ".tiktoken"}
    ]
    tokenizer = AutoTokenizer.from_pretrained(
        directory, local_files_only=True, trust_remote_code=False
    )
    targets = [(p["phase_id"], p["url"], p["model"]) for p in config["phase_targets"]]
    recipe = make_kv_recipe(
        targets,
        config["sources"],
        tokenizer,
        assets,
        materialized_row=args.materialized_row_v2,
        rpc_budget_s=args.rpc_budget_s,
        prompt_variant=args.prompt_variant,
        ack_time_policy=args.ack_time_policy,
    )
    # The caller must establish explicit 0700, including cleared special bits.
    import os
    import stat

    require(
        args.output.is_absolute()
        and stat.S_IMODE(args.output.parent.stat().st_mode) == 0o700
        and args.output.parent.stat().st_uid == os.getuid(),
        "private owned KV freeze parent required",
    )
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(recipe))
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(json.dumps({"recipe_sha256": sha(canonical(recipe)), "formal_result": False}))


if __name__ == "__main__":
    main()
