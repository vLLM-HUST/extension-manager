# Real native request/upload transport qualification, 2026-10-13

One freshly frozen TP2 request on physical 910B2 cards 3 and 6 (runtime 0 and 1,
visibility unset) completed a new phase nonce task and joined its actual native
API request mapping to 80 actual NPU block-table prefix readbacks: 40 from each
owned worker. The authenticated collector's post-request fsync prefix contained
82 rows: start, one API mapping, and 80 upload records. The exact `ee62` source
replay verifies intake chronology and the durable prefix. This is
**REAL_NATIVE_REQUEST_UPLOAD_TRANSPORT_NONFORMAL**.

Producer registration remains **CPU_REVIEW_CANDIDATE_ONLY** and formal admission
remains false. The runtime hardware transport observation is reported separately
from this registration classification. KV MOD effect, KV tensor equivalence,
attention consumption, full generation quality, full-window lost/duplicate
requests and the full objective remain unknown. This does not complete the
original manager-crash-afterprepare cell or the formal H3/H4 matrix. Formal
H3/H4 remain 0 and the submission decision remains NO-GO.

## Exact runtime and observations

The isolated venv was `/root/ecpa-native-upload-candidate-venv-20261013`.
Fresh wheel/source checks compared all packaged Python and ELF bytes:

| Component | Source/version | Wheel SHA prefix | Exact installed files |
| --- | --- | --- | ---: |
| Host | `a4bdbe74c1bdc1228e3cc19c61887225d35f16f8` | `a55e4e98` | 2651 |
| Ascend | `fcbb827af84f793939bf03d01a1dfe0338a0164c` | `be5a69b8` | 757 |
| KV MOD | `e343fc5ce6b4c64611a79df5d797b3db12cd6dac` | `581caaff` | 10 |
| Manager | build checkout `3be1eac03479bcae03239748b30fc85fe208f3d6` | `0498efa8` | 39 |
| Torch | `2.13.0+cpu` | archive metadata | 2384 |
| Torch NPU | `2.13.0rc1` | archive metadata | 1683 |
| Triton Ascend | `3.6.0+git92513dba` | archive metadata | 175 |

The archive records every full wheel digest. The Manager wheel is byte identical
to the known `0a6fdbc` runtime because all 39 packaged Python files are unchanged;
its hash does not uniquely identify a source commit. Fourteen model files were
freshly hashed. The frozen environment is an explicit allowlist with original
HOME, locale, CANN/ATB and a new empty private Triton cache. It contains no session
infrastructure environment payload. Generated cache artifacts and large
wheel/model bytes are omitted; their hash inventories and recorded input audits
are retained. Portable replay is not a fresh rebuild or model-file re-audit.

R2 froze config SHA `307b3b354ef54659c8c8b16c821f617c6ec8998337152d45c99119908af6131a`
and recipe SHA `5bed99bdc705299d909da94895c24386f89a98a9be79f5549f2e194765758a7d`.
It directly executed the frozen `owner.source.py` bytes, SHA
`6988b703d236187b127c8f65b83d74ac1e286721462ab401572eb096125b27c9`.
Manager PID 850786 minted launch `8afd41c4-228a-492c-9845-0c945dcf960d`; the
collector registered actual Host API PID 851014 and worker PIDs 851363/851364
after startup and before the sole HTTP request. Their epochs were observed, not
assigned external native identities before launch.

The HTTP response was 200 with the exact preregistered nonce and stop finish
reason, 69 prompt tokens and 39 completion tokens. Its ID was the frozen external
`chatcmpl-dfd18e4746b16c32422f8642a0cd34cb`; the native mapper observed internal
`chatcmpl-dfd18e4746b16c32422f8642a0cd34cb-aaa3cada`. No suffix guessing was used.
Response SHA is `751ba10e8217c053ffe35f54b3c1d93b30a6e40b509ae9fa50b9e2ce6180250f`;
native journal SHA is `436b1c6ca67d7a9cfae02467861f62ef81d61398556574b1066fea369cd3f1d9`.
Original kernel identities, owned sessions, port 29493 and both cards were clean
at termination. No fault or recovery result is inferred from this single request.

## Retained failure and scope of replay

R1's actual model backend reached health readiness, then its collector rejected
the output directory: mode 2700 inherited setgid from the container workspace.
An empty readiness record produced the secondary JSON error. No nonce request or
native upload journal was produced. Its source, original stderr, identities and
complete terminal cleanup evidence remain in the archive. R2 used an explicit
chmod 0700, checked actual UID/device/inode/mode and the journal parent before
collector startup, and passed a real CPU collector/HTTP/three-peer CLI precheck.
Those CPU fixtures never qualify as Host or NPU observations.

The 137-member raw archive SHA is
`b04787939bd54931e34e05beb2ca71e0a2df5df55846ecf78917783d654acf73`.
Source snapshots were copied after the run and compared to the prelaunch frozen
digests; they are not claimed as prelaunch observation files. Independent kernel,
environment, raw-response and terminal audits are explicitly late observations.
Subsequent counterexample audits reference this unchanged archive rather than
rewriting it.

The verifier recomputes raw membership/digests, exact source snapshot binding,
native handoff, request recipe, actual client HTTP status and sole backend POST,
native source/process/request/rank/device facts, raw-versus-parsed authenticated
statuses, final fsync seal, original owned session/PID epochs and both raw NPU
cleanup records. It executes only the independently fixed `ee62` snapshot hash;
the newer KV collector and historical `135a` compatibility cannot substitute it.
Missing rank, accept clocks or ACK proof explicitly fail qualification even when
the generic helper returns unknown without raising.

```sh
python -m experiments.formal_campaign.verify_native_interface \
  --manifest experiments/formal_campaign/artifacts/native-interface-20261013/manifest.json \
  --archive experiments/formal_campaign/artifacts/native-interface-20261013/raw.tar.gz
```

The raw owned-channel observations remain subject to the source/launcher trust
boundary; portable replay does not recreate a live kernel peer or remote
attestation. Generic table upload/readback proves neither a pending MOD rewrite
nor a later rewritten destination prefix, KV tensor equivalence or attention
consumption. The separate KV semantic campaign requires new sources, a new
tokenizer-bound long prompt and its own projection-to-later-upload predicate.
