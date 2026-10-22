# QoS scheduler host contract proposal

The extracted request model and ordering policy are independent of vLLM API and
scheduler classes. Runtime activation requires:

1. `vllm.request.qos-metadata.v1`: parse bounded TTFT/TBT/TTLT SLO fields at the
   API boundary and attach immutable metadata to the engine request.
2. `vllm.scheduler.request-snapshot.v1`: expose token counters, priority, arrival
   time, and local monotonic QoS state without exposing a mutable Request object.
3. `vllm.scheduler.ordering-policy.v1`: register waiting/running ordering keys;
   the extension may reorder but must not create a separate token budget.
4. `vllm.scheduler.output-observer.v1`: report generated-token and completion
   timestamps for SLO accounting.

Phase-one activation must fail closed for pipeline/data/context/expert parallel,
speculative decoding, KV disaggregation, LoRA, and other combinations not covered
by hardware and correctness tests. The API remains backward-compatible because
requests without QoS metadata retain native scheduling.
