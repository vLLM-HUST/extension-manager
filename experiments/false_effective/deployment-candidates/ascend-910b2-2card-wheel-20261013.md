# Current two-card wheel stack: registration candidate, not an H1 start

The 2026-10-13 candidate pins the installed vLLM-HUST wheel at
`973d9ef5acd2b9beb03e399dec1511a41fc941b5`, the vLLM-Ascend-HUST
PR #50 wheel at `54d31aaf204c77df8102cf30f8111c5baf3acadd`, CANN
9.1.0, the two allocated 910B2 devices (physical IDs 0 and 7), and the
Qwen2.5-7B-Instruct snapshot recorded in the adjacent SHA-256 file.
The observation describes the existing test venv, **not** a fresh install.

`installed_environment.py` hashed 48,054 non-bytecode installed files
(2,645,902,034 bytes) in that venv, including its interpreter and entry-point
scripts. It refused editable packages and site-packages symlinks; it did not
hash CANN, the driver, the model, or the host OS. Recompute the venv digest:

```sh
python experiments/false_effective/installed_environment.py \
  /tmp/ecpa-h1-native-env-20261012
```

Recompute the fail-closed stack audit:

```sh
python experiments/false_effective/deployment_stack_preflight.py \
  --requirements experiments/false_effective/deployment-candidates/ascend-910b2-2card-wheel-20261013.requirements.json \
  --observation experiments/false_effective/deployment-candidates/ascend-910b2-2card-wheel-20261013.observation.json
```

The sole **stack preflight** blocker is
`accelerator-plugin-runtime-unverified`: the plugin's checked vLLM commit is
`ced6857afa0ea7b2e3f0846a62e1394e90f15607`, while the host's recorded
upstream commit is `2d69083c4a09dfeb17d761ae96d2e571a628309c`.
A successful request with this pair is useful functional evidence, but does
not change either repository's checked provenance or qualify the pair for
formal admission. A reviewed, test-backed qualification for this exact fork
pair is needed; copying one commit into the other field would be false.

The wheel-only TP2 pilot separately reached HTTP health and completion 200,
then reported `runtime_effective` from a live host observer after a request.
Manager-owned shutdown removed its API, EngineCore, worker processes, port,
and NPU process use, and post-stop status dropped `runtime_effective`.
Those observations were not captured by the formal runner and cannot count
as a formal start. Beyond the stack mismatch, H1 still needs the reviewed
three-arm commands, independent lifecycle sources, deployment registration,
and nine validator-approved starts. No performance claim follows from this
candidate.
