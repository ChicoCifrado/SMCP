# Ejecucion local de las mismas cosas que corre el CI.
#
# Todo pasa por `delm gates`, que es la unica definicion de la lista de gates
# (delm/core/gates.py). Este Makefile no duplica esa lista: solo la invoca. Si
# anadiramos aqui un gate nuevo, el CI dejaria de correrlo y nadie se enteraria
# hasta que algo pasara sin comprobar.

PY := .venv/bin/python
DELM := .venv/bin/delm

.DEFAULT_GOAL := help

.PHONY: help gates gates-blocking lint types test slow test-all coverage demo demos clean install

help:  ## esta ayuda
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

gates:  ## todos los gates (lee, ruff, pyright, tests, slow)
	@$(PY) -m delm gates

gates-blocking:  ## solo los que bloquean el commit
	@$(PY) -m delm gates --blocking

lint:  ## ruff
	@$(PY) -m delm gates ruff

types:  ## pyright
	@$(PY) -m delm gates pyright

test:  ## suite completa (excluye `slow`)
	@$(PY) -m delm gates tests

slow:  ## tests marcados `slow` (handshake QUIC, subprocess)
	@$(PY) -m delm gates slow

test-all:  ## suite + slow
	@$(PY) -m delm gates tests slow

coverage:  ## suite con cobertura (el umbral vive en pyproject.toml)
	@$(PY) -m pytest --cov=delm --cov-report=term:skip-covered -q

demo:  ## demo por defecto (pipeline end-to-end)
	@$(DELM) demo

demos:  ## las 4 demos que el CI ejecuta
	@$(PY) -m delm.demo.run_demo
	@$(PY) -m delm.demo.run_security_demo
	@$(PY) -m delm.demo.run_taint_demo
	@$(PY) -m delm.demo.run_real_demo --dry-run

install:  ## instala el paquete con todos los extras
	@$(PY) -m pip install --upgrade pip
	@$(PY) -m pip install -e ".[all]"

clean:  ## borra caches y artefactos de test
	@rm -rf .pytest_cache .ruff_cache .pyright htmlcov .coverage
	@find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	@echo "limpio"
