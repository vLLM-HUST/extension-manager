# Unified communication host contract proposal

The extracted registry and decision policies are independent of torch, NCCL,
HCCL, and vLLM. Runtime activation requires a vLLM provider implementing:

1. `vllm.communication.backend.v1`: register a backend factory by unique name and
   device type; registration must reject collisions.
2. `vllm.communication.group.v1`: provide immutable ranks, local rank, world size,
   device identity, and existing process-group handles.
3. `vllm.communication.collectives.v1`: delegate individual collectives with an
   explicit failure result so the host can use its native fallback.
4. `vllm.communication.topology.v1`: provide topology facts used for decisions;
   the extension must not probe or reconfigure NICs and drivers itself.

GroupCoordinator remains lifecycle owner. The extension must not create a second
default process group, destroy host-owned communicators, or silently replace an
existing backend. Direct NCCL/HCCL C-API implementations require separate native
packages and hardware-specific validation.
