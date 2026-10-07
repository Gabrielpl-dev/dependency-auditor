.PHONY: run test coverage lint

# Run against the bundled offline example (no network). The example is expected
# to fail with exit 1, so the leading "-" stops make from treating it as an error.
run:
	-AUDITOR_OSV_FIXTURE=examples/osv-fixture.json ./app examples

test:
	python3 -m unittest discover -s tests -t tests -p 'test_*.py'

coverage:
	python3 tests/coverage_check.py

lint:
	ruff check .
