"""Manager phase domain entry; original native public proof/guards are unchanged."""

from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_native_authority import NativeAuthority


class ManagerPhaseAuthority(NativeAuthority):
    def _validate_epoch_selection(self, index):
        # No initial Host was ever enrolled or exposed. The actual second
        # semantic candidate is the first route generation, not a fabricated
        # generation-two public epoch. All original source/Plan/peer predicates
        # in _prepare_actual_epoch and attach_actual_epoch remain unchanged.
        require(
            index == 1
            and self.enrollment is not None
            and self.enrollment["generation"] == 1
            and self.route.generation is None
            and not self.native_epochs,
            "Manager recovery requires its first real post-fault enrollment",
        )


def main():
    import argparse
    import json
    import sys
    import threading
    from contextlib import suppress
    from http.server import ThreadingHTTPServer
    from pathlib import Path

    from experiments.formal_campaign import (
        h3_manager_phase_registration as registration,
    )
    from experiments.formal_campaign.h3_dynamic_authority import (
        canonical,
        check_ref,
        digest,
        require,
        serve_control,
    )
    from experiments.formal_campaign.h3_native_authority import (
        NativeJournal,
    )
    from experiments.formal_campaign.h3_native_http import NativeProxyHandler

    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("policy", "journal", "socket", "campaign", "receipt"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--start-id", required=True)
    parser.add_argument("--public-port", type=int, required=True)
    parser.add_argument("--owned-stdin-lifetime", action="store_true")
    args = parser.parse_args()
    validated = registration.validate_receipt_for_start(
        args.campaign, args.receipt, args.start_id
    )
    spec, original, start = validated.selected(args.start_id)
    receipt = validated.guard_receipt(args.start_id)
    require(
        start["policy"]["path"] == str(args.policy)
        and start["policy"]["sha256"] == args.policy_sha256
        and start["authority"]["journal"] == str(args.journal),
        "native registered authority argv differs",
    )
    policy = json.loads(check_ref(start["policy"]).read_bytes())
    recipe = json.loads(check_ref(start["recipe_template"]).read_bytes())
    guards = registration.build_plan_guards(
        spec, original, receipt, start, trusted_manager_handoffs=set()
    )
    journal = NativeJournal(args.journal, digest(canonical(policy)))
    authority = ManagerPhaseAuthority(policy, journal, plan_guards=guards)
    output = Path(
        recipe["arms"][start["arm"]]["phases"][0]["native_bootstrap"]["output"]
    ).parent
    authority.configure_start(start=start, recipe=recipe, output=output)
    require(recipe["authority"]["socket"] == str(args.socket), "native socket differs")
    server = ThreadingHTTPServer(("127.0.0.1", args.public_port), NativeProxyHandler)
    server.authority = authority
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.owned_stdin_lifetime:
        threading.Thread(
            target=serve_control, args=(args.socket, authority), daemon=True
        ).start()
        try:
            sys.stdin.buffer.read()
        finally:
            with authority.lock:
                authority._close("independent native owner lifetime ended")
            server.shutdown()
            server.server_close()
            authority.close_collectors()
            journal.close()
            with suppress(FileNotFoundError):
                args.socket.unlink()
    else:
        serve_control(args.socket, authority)


if __name__ == "__main__":
    from experiments.formal_campaign.h3_manager_phase_authority import (
        main as canonical_main,
    )

    canonical_main()
