"""Actual independent bootstrap entry, never a formal receipt or synthetic run."""

from __future__ import annotations


def request_schedule(start_id):
    return [
        dict(
            all_index=i,
            request_id=f"{start_id}/"
            + ("warmup-" + f"{i:04d}" if i < 16 else "measured-" + f"{i - 16:04d}"),
            kind="warmup" if i < 16 else "measured",
            selected=i < 16 or (i - 16) % 16 == 0,
        )
        for i in range(272)
    ]


def main():
    # The independent observer executes the shared real producer; it retains
    # actual root/Host/health/client/cleanup bytes even when qualification fails.
    from .conditional_root_observer import main as observe

    observe()


if __name__ == "__main__":
    main()
