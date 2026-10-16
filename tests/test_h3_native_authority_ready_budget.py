"""Virtual-clock control-plane boundary; no process launch or model inference."""

from experiments.formal_campaign import h3_dynamic_runner as m


def test_original_dynamic10s_versus_registered_native_startup_and_no_clock_reset():
    original = {"probe": {"ready_timeout_s": 900, "request_timeout_s": 10}}
    launched, socket_ready = 100.0, 112.0
    native_deadline = m.authority_readiness_deadline(
        original, native=True, launched_monotonic=launched
    )
    dynamic_deadline = m.authority_readiness_deadline(
        original, native=False, launched_monotonic=launched
    )
    assert dynamic_deadline < socket_ready < native_deadline
    assert native_deadline == 1000.0
    assert socket_ready + 900 != native_deadline
    assert original["probe"]["request_timeout_s"] == 10
