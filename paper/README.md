# Research evidence and experiment validation

The manuscript and PDF build have moved to the separate paper repository.
The [historical manuscript and build instructions](https://github.com/vLLM-HUST/extension-manager/tree/6a26ae88acc14591817df9069b7c884dd1a4f86d/paper) remain available at their original revision.

This directory contains the evidence projections and validators used by the
experiment repository. Set up the verified [benchmark originals](../docs/benchmark-originals.md)
before running the checks.

```sh
make -C paper validate-results
make -C paper check-attention-source-summary
```

The [claim-to-experiment matrix](../docs/research/claims-to-experiment-matrix.json)
and the [formal campaign protocol](../experiments/formal_campaign/protocol.json)
specify the research hypotheses, comparison arms, and evaluation thresholds.
Regenerate evidence projections into a fresh external output directory and
keep the archived originals as inputs for independent replay.
