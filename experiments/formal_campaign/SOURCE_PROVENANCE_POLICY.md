# Prospective full-tuple source admission

The historical H3 v2 and H4 v1 issuers checked remote-main ancestry for Manager
and Host, but copied Ascend/plugin SHAs from fixed identity. This change does
not reinterpret their archived receipts, H1 outcomes, or nonformal native
qualifications. The original protocol did not require all four components to
be merged to main.

New CLI issuance requires `source_provenance_policy` inside the campaign bytes
before authority/launch registration and first launch. It issues H3 v3/H4 v2.
A policy example (repository identities must match the actual campaign) is:

```json
{
  "schema": "ecpa-full-tuple-source-provenance-policy/v1",
  "components": {
    "manager": {"repository": "vLLM-HUST/extension-manager", "requirement": "merged-main"},
    "host": {"repository": "vLLM-HUST/vllm-hust", "requirement": "merged-main"},
    "accelerator": {"repository": "vLLM-HUST/vllm-ascend-hust", "requirement": "published-commit"},
    "plugin:ascend-kvcompress": {"repository": "vLLM-HUST/vllm-ascend-kvcompress-hust", "requirement": "published-commit"}
  }
}
```

Manager/Host keep their original merged-main requirement. Every plugin in the
fixed identity requires exactly one `plugin:<name>` policy. `published-commit`
means that the declared GitHub repository actually serves the exact requested
SHA; it does not claim main ancestry. A campaign may instead explicitly require
`merged-main` for Ascend/plugin. No implicit four-component merge restriction
or unsupported declared-sourceproof fallback is installed.

Pass `--source-repositories locations.json` to either registration CLI. The
object maps each policy role to `{ "path": "/absolute/clean/checkout",
"remote": "origin" }`. Manager/Host locations must exactly equal the existing
issuer arguments. These are actual checkout locations, not evidence supplied
by the owner. The issuer resolves each canonical github.com HTTPS/SSH remote,
fetches the exact SHA into a newly empty temporary bare object store, checks its
tree, checks requested main ancestry when declared, then verifies clean exact
HEAD/tree in the checkout. The empty object store matters: ordinary `git fetch`
from an existing checkout can succeed for a local unpublished SHA without the
remote serving it. A local/mirror/foreign-host URL with the same path cannot
admit official source identity.

The new helper and receipt schema must themselves be exact bytes in the
admitted Manager commit. The receipt binds those bytes, policy, all requested
and remotely observed commits, source trees, and explicit merge observations.
Runner/analyzer share one validator: a campaign declaring this policy cannot
consume a legacy receipt, omit a component, substitute another SHA, or change
the policy/source binding. Old campaign/receipt formats remain readable for
retained historical evidence and CPU fixtures; new registration CLI issuance
has no legacy fallback. Fetch/unavailable/local-only/dirty/missing-policy
failures write no registration receipt and leave source admission unverified.
These failures are not recovery objective observations.

## Remaining semantic boundary

`semantic_campaign_prospective.py` emits a source-bound, non-executable draft
containing all original 25 H3 cells (225 scheduled starts) and four H4 cells
(36 starts), including unsupported/unverified cells. It fills no objective,
identity, warm-state, wheel, or effect result with guessed values. Formal
completed starts remain zero; startup violation still requires both percent
and absolute thresholds to be exceeded.

Old effective aggregation exists, but the actual authorization path consumes
invocation events and explicitly rejects formal semantic evidence. The new
source admission fixes a deployment identity edge; it does not register the
native tensor/operator receipts as Plan obligations, bind them to authority
generation/lease/replacement epochs, implement a private authority probe before
public exposure, or cover all extension classes. Successful selected logical
KV byte qualification and future OP qualification remain separate nonformal
facts. KV full quality and formal H3/H4 outcomes remain unknown.

Tests use real CPU Git repositories and fetch/tree/dirty/ancestry operations;
only the GitHub transport URL is explicitly mapped to the local fixture. They
are not official repository publication evidence or hardware qualification.
