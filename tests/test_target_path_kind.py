"""§0/§4.1 of the plugin-additions instructions: TargetKind.PATH must be
purely additive (existing host/url Target data keeps loading unmodified),
and a registered `path` target's address must always be the fully-resolved,
symlink-free real directory."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.core.models import TargetKind, TargetPathError, resolve_path_target_address
from pownforge.core.policy import ScopePolicy

runner = CliRunner()


def test_resolve_path_target_address_returns_the_real_absolute_path(tmp_path: Path) -> None:
    real_dir = tmp_path / "repo"
    real_dir.mkdir()
    link = tmp_path / "link-to-repo"
    link.symlink_to(real_dir)

    resolved = resolve_path_target_address(str(link))

    assert resolved == str(real_dir.resolve())


def test_resolve_path_target_address_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(TargetPathError, match="does not exist"):
        resolve_path_target_address(str(tmp_path / "nope"))


def test_resolve_path_target_address_rejects_a_file(tmp_path: Path) -> None:
    f = tmp_path / "not-a-dir.txt"
    f.write_text("x")
    with pytest.raises(TargetPathError, match="is not a directory"):
        resolve_path_target_address(str(f))


def test_existing_host_and_url_targets_still_load_after_adding_the_path_kind(tmp_path: Path) -> None:
    """A targets.yaml written before TargetKind.PATH existed (only host/url
    ever used) must still parse -- adding a new enum member must not affect
    deserialization of already-registered targets."""
    config = tmp_path / "targets.yaml"
    config.write_text(
        "targets:\n"
        "  legacy-host:\n"
        "    kind: host\n"
        "    address: 127.0.0.1\n"
        "  legacy-url:\n"
        "    kind: url\n"
        "    address: http://lab-web:3000\n"
    )
    policy = ScopePolicy.load(config)
    assert policy.resolve("legacy-host").kind == TargetKind.HOST
    assert policy.resolve("legacy-url").kind == TargetKind.URL


def test_target_add_cli_resolves_symlinks_for_path_kind(tmp_path: Path) -> None:
    real_dir = tmp_path / "repo"
    real_dir.mkdir()
    link = tmp_path / "link-to-repo"
    link.symlink_to(real_dir)
    config = tmp_path / "targets.yaml"

    result = runner.invoke(
        app,
        ["target", "add", "src-repo", "--address", str(link), "--kind", "path", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    policy = ScopePolicy.load(config)
    target = policy.resolve("src-repo")
    assert target.kind == TargetKind.PATH
    assert target.address == str(real_dir.resolve())


def test_target_add_cli_rejects_a_missing_path(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    result = runner.invoke(
        app,
        ["target", "add", "src-repo", "--address", str(tmp_path / "nope"), "--kind", "path", "--config", str(config)],
    )
    assert result.exit_code != 0
