# Findings

## 2026-10-12 venue audit

- OSDI '27 explicitly includes systems for machine learning, secure and
  reliable systems, and management/troubleshooting of complex systems.
- ECPA's systems mechanism fits the Research track. Current evidence does not
  establish the deployment scale or operational experience expected by the
  Operational Systems track.
- Abstract registration is due 2026-12-01 22:59 UTC and the full paper is due
  2026-12-08 22:59 UTC.
- The submission body limit is 12 pages plus unlimited references.
- A preliminary first-pages review may be introduced; USENIX will decide at
  least one month before the deadline.
- Because ECPA and its draft are public, the submitted paper must use a
  different, unpublicized system name and remove searchable release/repository
  identifiers. An anonymous author line alone is insufficient.
- The public draft still reports the matched formal experiment and H1--H4 as
  incomplete. The pinned Ascend run is lifecycle qualification, not the
  formal comparison and not a performance result.
- The 2026-10-12 Tectonic build produced 14 PDF pages. A later PDF text-page
  audit corrected the initial page count: body text extends into page 13 and
  References begins partway through page 13. The current draft exceeds the
  OSDI '27 limit of 12 body pages; the final rendering needs a real trim and
  a page-boundary check.
- Research-matrix validation reports 4 claims, 5 experiments, a first study in
  pre-admission with 9 planned starts, and an unregistered deployment. This is
  the primary submission blocker.
- vLLM-HUST PR #27 was merged as
  `b326fafe5405b9996db9c9f0d7758536148ecc9b`; its final head and tree are
  `f3eb4b09ba91a1720c4e35de41a91e6dc351fd5b` and
  `bcdb8c810b60c11e77cb8af2002bd9039600b808`. APei-520 completed an
  affirmative line review before merge. The historical PR check still records
  a Buildkite test-tethering failure; current host `main` subsequently wires
  the evidence test, so this audit records the merge/review facts without
  describing the historical PR CI as green.
- Retiring those two stale producer blockers does not admit the experiment.
  The verified adapter registry is empty, the deployment identity is not
  frozen, and deployment commands have not been reviewed.
- The 2026-09-21 Ascend deployment candidate captured an eight-device host,
  old runtime/plugin source commits, an image built from different commits,
  and batch-invariant mode. Its checked preflight is blocked on runtime/plugin
  compatibility, binary/source identity, and runtime mode. It remains a
  historical candidate, not a current deployment registration.
- On 2026-10-12 this container exposes only `/dev/davinci0` and
  `/dev/davinci7`, both Ascend 910B2, with no NPU processes shown by
  `npu-smi info`. CANN 9.1.0 is installed; the Docker CLI is unavailable.
  The local vLLM-HUST checkout is detached at `d0f22d2bda562156e4dbf433ce645e1769b4f804`,
  while its tracked `origin/main` is `4f61604bea01ce56afc320e0f0566166fd79a562`.
  The old eight-device observation cannot supply today's frozen topology or
  command fingerprints. No device run was started in this audit.
- The two visible 910B2 devices satisfy the first study's minimum of two
  distinct worker slots. The installed `vllm`/`vllm-ascend` are 0.23.0 and
  `torch`/`torch-npu` are 2.10.0, while current host and accelerator-plugin
  `main` require torch 2.13.0; a current stack is not yet pinned or runnable.
- On 2026-10-12 the fetched host `origin/main` is
  `4f61604bea01ce56afc320e0f0566166fd79a562` and the fetched
  accelerator-plugin `origin/main` is
  `e5870e657a2add3182551c70bbad5919fc96d899`. The plugin's checked
  upstream vLLM pin is `ced6857afa0ea7b2e3f0846a62e1394e90f15607`,
  which is not an ancestor of the host `main`. The available `torch-npu`
  2.13.0rc1 wheel does not resolve this source-compatibility mismatch or
  supply a reviewed deployment image.
- An OSDI related-work audit places AlpaServe as serving-performance context,
  not as a substitute for the three-arm H1 activation-safety baseline. The
  paper should add such peer-reviewed context only while fitting the 12-page
  body and preserving the exact experimental distinction.
- The reference ExposureGate previously read the deterministic adapter's
  in-memory `route` field in stage, observe, and rollback paths. An external
  route owner cannot supply that field as authoritative state. The loopback
  integration slice replaces those reads with bounded route queries and adds
  a separate HTTP authority process. Its current proof remains synthetic and
  is outside the formal-real aggregate.

Official source:
<https://www.usenix.org/conference/osdi27/call-for-papers>
