"""Manager-owned coordinator admission contract; no Host import required."""
from types import SimpleNamespace

import pytest

from experiments.formal_campaign import h3_observer_live_rebind as manager


def test_unissued_authority_contract_rejects_before_any_socket(monkeypatch):
    called=[]
    monkeypatch.setattr(manager.socket,'socket',lambda *a,**k:called.append(True))
    with pytest.raises(ValueError,match='source-owned observer authority'):
        manager.Coordinator(SimpleNamespace(start={},policy={}))
    assert called==[]

