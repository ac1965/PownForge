from pownforge.core.secrets import mask_command


def test_masks_two_token_flag_value() -> None:
    command = ["tool", "--header", "user:pass", "--target", "x"]
    assert mask_command(command) == ["tool", "--header", "***", "--target", "x"]


def test_single_letter_flags_are_not_covered_by_the_keyword_heuristic() -> None:
    # -H is a common shorthand for --header in several tools, but a bare
    # single letter carries no keyword to match against -- this is a known
    # limit of the heuristic (see docs/handbook.md §2 全体アーキテクチャ), not a bug.
    command = ["tool", "-H", "user:pass"]
    assert mask_command(command) == command


def test_masks_long_flag_two_token_value() -> None:
    command = ["curl", "--header", "Authorization: Bearer xxx", "http://x"]
    assert mask_command(command) == ["curl", "--header", "***", "http://x"]


def test_masks_equals_form() -> None:
    command = ["tool", "--cookie=abc123", "--target", "x"]
    assert mask_command(command) == ["tool", "--cookie=***", "--target", "x"]


def test_masks_password_flag() -> None:
    command = ["tool", "--password", "foo", "--user", "bob"]
    assert mask_command(command) == ["tool", "--password", "***", "--user", "bob"]


def test_matches_substring_case_insensitively() -> None:
    command = ["tool", "--Api-Key", "xyz"]
    assert mask_command(command) == ["tool", "--Api-Key", "***"]

    command = ["tool", "--AUTH-CRED", "xyz"]
    assert mask_command(command) == ["tool", "--AUTH-CRED", "***"]


def test_does_not_mask_value_when_next_token_is_another_flag() -> None:
    # No separate value was actually given -- --token here is a bare/boolean
    # flag, so the following flag must not be swallowed as its value.
    command = ["tool", "--token", "--verbose", "x"]
    assert mask_command(command) == ["tool", "--token", "--verbose", "x"]


def test_leaves_non_sensitive_flags_untouched() -> None:
    command = ["nmap", "-sV", "-Pn", "-p", "80,443", "127.0.0.1"]
    assert mask_command(command) == command


def test_does_not_mutate_input() -> None:
    command = ["tool", "--password", "foo"]
    original = list(command)
    mask_command(command)
    assert command == original
