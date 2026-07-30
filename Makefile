.PHONY: install lint typecheck test verify performance

install:
	python -m pip install -e ".[dev]"

lint:
	python -m ruff check src tests

typecheck:
	python -m mypy src

test:
	python -m pytest

verify: lint typecheck test

performance:
	python -m pytest tests/performance -m performance -q
