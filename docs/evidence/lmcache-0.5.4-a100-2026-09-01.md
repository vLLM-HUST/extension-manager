# LMCache 0.5.4 MP acceptance evidence — A100, 2026-09-01

This probe validates the LMCache Host Provider against an official, immutable
LMCache artifact. It is a CPU/SHM protocol test, not a model benchmark and not
evidence that the Manager owns the LMCache service lifecycle.

## Immutable inputs

- host: `a100-dev`, NVIDIA driver `580.173.02`;
- image: `lmcache/standalone:v0.5.4-cu129`;
- image digest:
  `sha256:8d6d27db4c9b12dc247d3e0a15f851ee5c968cba39af4b7762e3dfab69d6b1a8`;
- LMCache endpoint version: `0.5.4`, upstream commit `3e11b8ed`;
- Manager wheel SHA-256:
  `3954fa13d8130af877fecdeebd4fabb1b4c28268fa70197920a66af23369073e`;
- LMCache profile wheel SHA-256:
  `ef2146f3ac33c506e59126c724a47f0d64ba09816bea72f534920fe652079033`.

The service used one worker, a 0.03 GiB L1, a four-token chunk, no GPU device,
and loopback-only host ports. The image reported
`accelerator available: False`. The first attempted HTTP port was already in
use; Docker rejected the container before start, after which the isolated
probe used `127.0.0.1:26555` for ZMQ and `127.0.0.1:28080` for HTTP.

## Data path

The upstream `lmcache bench server` command ran with:

```text
--mode cpu --transfer-mode lmcache_driven
--kvcache-shape-spec (2,8,4,1,8):float16:2
--num-tokens 7 --start 0 --end 2
```

It used POSIX SHM to exercise the same MP protocol surface as a worker:
registration, LOOKUP, STORE, warm LOOKUP, RETRIEVE, HTTP CHECKSUM, and
unregistration. Results:

- two requests, two successful checksums, zero checksum failures;
- pass rate 100%;
- cold STORE succeeded for both requests;
- the second warm lookup hit 2/2 chunks;
- RETRIEVE returned all eight tokens;
- the warm checksum matched the stored checksum;
- the server recorded three L1 objects and 12,288 bytes before cleanup.

No probe SHM object remained after the client exited.

## Manager lifecycle projection

The profile was discovered from its wheel, configured, and enabled. With the
service running, `status` contained:

```text
installed discovered compatible configured enabled reachable healthy
```

Evidence included HTTP 200, remote `/lmc_version` value `0.5.4`, and satisfied
host/API/protocol ranges. `plan` contained only `render_connector_config` and
`check_service`; both were non-mutating. `render` emitted the official
`LMCacheMPConnector` configuration, and `run --dry-run` merged it into
`--kv-transfer-config` without a fabricated module path.

After the external operator stopped the service, enabled intent persisted and
the state became:

```text
installed discovered configured enabled degraded
```

Compatibility was deliberately unverified: the Manager did not use its local
LMCache package as proof of the unreachable remote service version. After the
external operator restarted the service, the seven healthy states returned
without reinstalling, reconfiguring, or re-enabling the extension.

Finally, the Manager disabled and forgot its own intent. The external operator,
not the Manager, then stopped and removed the temporary service container. No
cache-clear, eviction, service-start/stop, image removal, or GPU operation was
issued by Provider/Core.

## Coexistence observation

The probe never received a GPU device. During the run an unrelated user systemd
unit, `sage-mate-vllm-nvidia-engine.service`, restarted its vLLM workers; GPU
memory consequently changed independently and returned to the pre-probe value
of about 72,091 MiB per device. The final temporary-container cleanup left that
workload unchanged.

## Result

The LMCache 0.5.4 MP Provider gate passes for package discovery, exact remote
version compatibility, health, non-mutating render/plan, CPU-SHM
LOOKUP/STORE/RETRIEVE/CHECKSUM, outage degradation, recovery, disable, and
forget. This does not unblock alpha by itself: the vLLM/BidKV upstream contract
and Production Stack controller/metrics/traffic gates remain open.
