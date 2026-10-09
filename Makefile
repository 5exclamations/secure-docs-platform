PY ?= python3
VENV ?= .venv

.PHONY: secrets venv lint typecheck test security up down demo

secrets:        ## generate a local .env with random secrets
	./scripts/gen_env.sh

venv:
	$(PY) -m venv $(VENV) && $(VENV)/bin/pip install -r requirements-dev.txt

lint:
	$(VENV)/bin/ruff check app tests migrations && $(VENV)/bin/ruff format --check app tests migrations

typecheck:
	$(VENV)/bin/mypy

test:           ## starts throwaway postgres/redis/s3 automatically when binaries are present
	$(VENV)/bin/pytest --cov=app --cov-report=term-missing

security:
	$(VENV)/bin/bandit -q -r app -c pyproject.toml && $(VENV)/bin/pip-audit -r requirements.txt

up: secrets
	docker compose up --build -d

down:
	docker compose down -v

demo:           ## end to end walkthrough against a running stack
	$(VENV)/bin/python scripts/demo.py --base-url http://localhost:8000
