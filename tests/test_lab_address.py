from __future__ import annotations

import pytest

from pownforge.core.lab import LabError, resolve_lab_target_address
from pownforge.core.models import TargetKind


def test_host_kind_uses_name_as_address() -> None:
    assert resolve_lab_target_address("lab-net", TargetKind.HOST, "http", None) == "lab-net"


def test_url_kind_builds_scheme_host_port() -> None:
    assert (
        resolve_lab_target_address("lab-web", TargetKind.URL, "https", 3000)
        == "https://lab-web:3000"
    )


def test_url_kind_without_port_raises() -> None:
    with pytest.raises(LabError):
        resolve_lab_target_address("lab-web", TargetKind.URL, "http", None)
