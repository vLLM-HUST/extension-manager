# Explicit source read predicates (research adapter)

This candidate adds a typed positive-integer configuration read requirement to `ProviderPlan`. `reject_conflicting_plans` intersects requirements by provider and configuration path and can also check actual declared configuration values. Existing write/resource checks remain. Empty requirements preserve previous constructor behavior and `plan_dict` keys. This does not automatically discover source dependencies or make a manifest/runtime qualification.

The separate research entry calls the real manifest loader, `plan_for`, and compiler. It verifies full source and manifest SHA bytes and stable file states, then explicitly attaches reviewed declarations. It never imports MOD/Host implementations or launches the final command. The example declares two independent source facts: Pipeline commit4b8bafda91d2db6d8cf5f689a03eb13734bfa510 `policy.py:50–54` rejects PP<=1; KV commitd4090a888f971ea50e874cdf86bf63a8e22e647f `stateful.py:221–230` requires PP=1. The generic compiler has no MOD-specific branches. Full raw SHA, original Git blob and commit references are in `source-read-predicate-example.json`. Git references document provenance; this entry checks content, not remote Git promotion.

Place those exact source trees at `SOURCE_ROOT/pipeline` and `SOURCE_ROOT/kv`. Supply a JSON string array of the intended final Host argv including exactly one positive PP and TP flag each:

```sh
python -m experiments.real_mod_composition.source_constraint_preflight --source-root SOURCE_ROOT --profiles experiments/real_mod_composition/source-read-predicate-example.json --launch-argv final-host-argv.json
```

Exit2 is a source prelaunch rejection; exit0 only means these declared predicates passed. Other Host/model/API constraints, installed wheel closure and actual single-MOD effectiveness still require their own proof. A declaration is trusted analyst input, not an inference or authenticity claim. The source oracle must be frozen separately and never supplied to this command. Source paths stay beneath the supplied root; source binding errors are errors rather than conflict verdicts. The CLI does not install this research adapter into the normal manifest/CLI path.

The original unmodified compiler did not detect this PP contradiction through declared merge checks. That stock negative and the source-derived oracle remain separately preserved development evidence; the new candidate cannot retroactively count as merged ECPA detection or native conflict. Two compiler plan orders are not native installation/load orders. No common supported Host or fresh singleton qualification was established for this source pair. The two test manifest fixtures preserve original bytes; tiny source-binding test files explicitly are fixtures, not production MOD code.
