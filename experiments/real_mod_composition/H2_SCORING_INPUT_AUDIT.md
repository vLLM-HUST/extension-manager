# H2 input-verdict exclusion

The external-authority source oracle remains a source-level conflict analysis.
Its historical prediction passes a prediagnosed `ownership_conflicts` string to
`ProductionStackProvider.check`. The provider consumes that report rather than
deriving the conflict from the two independently developed controllers.

The audit retains real calls to the exact source-matched provider with and
without that report. With it, compatibility is false. Removing only the report
leaves compatibility unknown, because host/API/protocol facts are unavailable;
unknown is not admission. Thus the old match is report-consumption evidence,
not an independent conflict-detection true negative. Historical oracle,
prediction, configuration and old aggregate bytes remain unchanged.

Current independent H2 scoring excludes this case: the definite subset is
four cases, TP=2/TN=2/FP=FN=0. It remains incomplete and supports no population
claim. A new source-derived detector needs independently frozen inputs and a
new prediction before this external-authority surface can be scored again.
This audit supplies no Kubernetes runtime or performance evidence.

Reproduce the actual provider comparison and scoring exclusion:

```sh
PYTHONPATH=src:. python -m experiments.real_mod_composition.h2_scoring_input_audit
```
