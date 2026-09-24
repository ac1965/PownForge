"""refactor §13: requires/provides is a machine-checked dependency graph
between Actions in the same AttackOperation, evaluated by
OperationRunner.execute() (core/operation/runner.py) via
find_unmet_requirements()/provided_tags() below. Kept separate from the
existing Capability enum (core/models/primitive.py), which classifies an
action's own effect type -- see docs/handbook.md's terminology table."""

from __future__ import annotations

from pownforge.core.operation import Action, ActionKind, ActionStatus, AttackOperation, AttackPhase
from pownforge.core.operation.model import find_unmet_requirements, provided_tags


def _action(**overrides) -> Action:
    defaults = dict(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network")
    defaults.update(overrides)
    return Action(**defaults)


def test_provided_tags_only_counts_completed_actions() -> None:
    operation = AttackOperation(
        name="op",
        actions=[
            _action(id="a1", provides=["credential"], status=ActionStatus.COMPLETED),
            _action(id="a2", provides=["admin-session"], status=ActionStatus.APPROVED),
        ],
    )
    assert provided_tags(operation) == {"credential"}


def test_find_unmet_requirements_is_empty_when_nothing_required() -> None:
    operation = AttackOperation(name="op", actions=[])
    assert find_unmet_requirements(operation, _action(requires=[])) == []


def test_find_unmet_requirements_is_empty_once_a_prior_action_provides_the_tag() -> None:
    operation = AttackOperation(
        name="op",
        actions=[_action(id="a0", provides=["credential"], status=ActionStatus.COMPLETED)],
    )
    assert find_unmet_requirements(operation, _action(id="a1", requires=["credential"])) == []


def test_find_unmet_requirements_lists_missing_tags_in_order_deduplicated() -> None:
    operation = AttackOperation(
        name="op",
        actions=[_action(id="a0", provides=["credential"], status=ActionStatus.COMPLETED)],
    )
    action = _action(id="a1", requires=["credential", "admin-session", "credential", "root-shell"])
    assert find_unmet_requirements(operation, action) == ["admin-session", "root-shell"]
