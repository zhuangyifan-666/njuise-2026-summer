from repoproof.collectors.secrets import shannon_entropy


def test_entropy_is_zero_for_repeated_value() -> None:
    """Catches entropy code that considers a single-symbol value random."""
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_is_high_for_mixed_value() -> None:
    """Catches entropy code that misses a diverse assignment value."""
    assert shannon_entropy("Q9!sL2@pX7#vN4$k") > 3.5
