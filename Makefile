.PHONY: help test suite scan trend api plugins benchmark dist clean

help:
	@echo "WinSecure Build & Automation Targets:"
	@echo "  make test       - Run full automated test suite"
	@echo "  make suite      - Run EVERYTHING: tests + integrity + E2E scan + plugins"
	@echo "  make scan       - Run standard security assessment"
	@echo "  make trend      - Analyze posture drift across scan history"
	@echo "  make api        - Start the REST API & webhook server"
	@echo "  make plugins    - List installed WinSecure plugins"
	@echo "  make benchmark  - Run performance and throughput benchmarking"
	@echo "  make dist       - Package production ZIP archive with SHA-256"
	@echo "  make clean      - Clean temporary artifacts and caches"

test:
	python scripts/run_tests.py

suite:
	python run.py suite

scan:
	python run.py scan

trend:
	python run.py trend

api:
	python run.py api --no-browser

plugins:
	python run.py plugins

benchmark:
	python run.py benchmark --iterations 5

dist:
	python scripts/build_dist.py

clean:
	rm -rf __pycache__ .pytest_cache build dist *.egg-info /tmp/ws_*
