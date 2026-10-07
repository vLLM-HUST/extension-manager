# Pegaflow ECPA 0.3 clean-wheel closure

1. Audit current Manager and Pegaflow main commits and PR #31 evidence.
2. Build the Manager, Pegaflow runtime, and Pegaflow provider wheels from clean sources.
3. Install only those wheels in an isolated Python 3.12 environment and exercise discovery, inspection, compatibility, intent, planning, rendering, status, disable, rollback, forget, and uninstall boundaries.
4. Confirm that the absent external Pegaflow service fails closed and that Manager does not create or kill externally owned processes.
5. Correct the Manager support matrix only where the clean-wheel evidence supports it; run the full Manager quality gates and open/merge a narrow PR after CI.
6. Reconcile the public catalog/plugin page as a preview entry and verify the deployed feed without claiming runtime effectiveness or performance.

