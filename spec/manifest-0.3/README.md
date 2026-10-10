# ECPA Extension Manifest 0.3

This directory freezes the product Manifest 0.3 data shape. The stable schema
identifier is the JSON value `"schema_version": "0.3"`.

- `manifest.schema.json` is the normative structural schema.
- `conformance-vectors.json` contains accepted and rejected documents.
- `migration-vectors.json` records explicit 0.2 migration and exact rollback.

The Python parser is a second normative implementation for semantics that JSON
Schema cannot express, including PEP 440 versions and version ranges. CI
requires the schema and parser to agree on every conformance vector.

Unknown fields and unknown schema revisions fail closed. Compatible additions
must use a future schema identifier; the meaning of a field in 0.3 will not be
changed in place. `0.3-experimental` remains readable as a compatibility alias
for already published MOD wheels, but new and migrated manifests should emit
`0.3`.

Manifest stability does not authorize a Manager package release and does not
qualify any MOD, host, device, runtime effect, or performance claim.
