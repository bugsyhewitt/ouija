# ouija — developer tasks.
#
# The agentic suite (Packet 02) is headless: every test runs in-process against
# the in-repo deliberately-vulnerable lab (no GUI, no external model, no
# persistent server, no network egress beyond the local OOB collector).

PY ?= python

.PHONY: ouija-test test agentic-test lint-probes help

help:
	@echo "make ouija-test     - run the full test suite (v0.1 + agentic), headless"
	@echo "make agentic-test   - run only the agentic (Packet 02) test suite"
	@echo "make lint-probes    - print the probe catalog + OWASP mapping (sends nothing)"

# §19 deliverable: the ship-gate.
ouija-test test:
	$(PY) -m pytest -q

agentic-test:
	$(PY) -m pytest -q tests/agentic

lint-probes:
	$(PY) -m ouija.agentic_cli list-probes --format table
