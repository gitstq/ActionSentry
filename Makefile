.PHONY: install test scan lint clean

install:
	pip install -e .

test:
	python tests/test_runner.py

scan:
	python -m actionsentry scan tests/

scan-json:
	python -m actionsentry scan tests/ --json

scan-sarif:
	python -m actionsentry scan tests/ --sarif

scan-fix:
	python -m actionsentry scan tests/ --fix

list-rules:
	python -m actionsentry list-rules

version:
	python -m actionsentry version

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .eggs/ 2>/dev/null || true
