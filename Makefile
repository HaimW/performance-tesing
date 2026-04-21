SHELL := /bin/bash

# Read worker count from config.yaml at parse time so $(WORKER_COUNT) works in recipes
WORKER_COUNT := $(shell python3 -c \
	"import yaml; print(yaml.safe_load(open('config.yaml'))['workers']['count'])" \
	2>/dev/null || echo 10)

.PHONY: env run scale clean clean-all logs report

## Generate .env from config.yaml (Docker Compose reads this for variable interpolation)
env: config.yaml
	@python3 -c "\
import yaml; \
c = yaml.safe_load(open('config.yaml')); \
print('USERS='        + str(c['load']['users'])); \
print('SPAWN_RATE='   + str(c['load']['spawn_rate'])); \
print('RUN_TIME='     + str(c['load']['run_time'])); \
print('WORKER_COUNT=' + str(c['workers']['count'])); \
print('CSV_PREFIX='   + c['output']['csv_prefix'])" > .env
	@echo "Generated .env from config.yaml"

## Start master + N workers (N = workers.count from config.yaml)
run: env
	mkdir -p reports && chmod 777 reports
	docker compose up \
		--scale worker=$(WORKER_COUNT) \
		--abort-on-container-exit \
		--remove-orphans

## Scale to a custom number of workers: make scale WORKERS=20
scale: env
	mkdir -p reports && chmod 777 reports
	docker compose up \
		--scale worker=$(or $(WORKERS),$(WORKER_COUNT)) \
		--abort-on-container-exit \
		--remove-orphans

## Stop all containers (CSV files in ./reports/ are preserved)
clean:
	docker compose down --remove-orphans

## Stop all containers and wipe all CSV output
clean-all:
	docker compose down --remove-orphans
	rm -rf reports/*

## Stream live logs from all containers
logs:
	docker compose logs -f

## Show CSV files produced by the last run
report:
	@echo "CSV files in ./reports/:"
	@ls -lh reports/*.csv 2>/dev/null || echo "(no CSV files yet — run 'make run' first)"
