PYTHONPATH := src
export PYTHONPATH

DATA ?=

.PHONY: test ingest serve

test:
	python3 -m unittest discover -s tests -v

ingest:
	python3 -m salesintel.ingest --input "$(DATA)" --out data/signalboard.sqlite

serve:
	python3 -m salesintel.app --db data/signalboard.sqlite --host 127.0.0.1 --port 8765
