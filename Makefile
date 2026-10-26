.DEFAULT_GOAL := help

.PHONY: help start logs status
help:
	@echo Targets: start, logs, status

# Start Wazuh and the CrowdStrike bridge in this Compose project.
start:
	docker compose up -d --build

logs:
	docker compose logs -f wazuh.indexer wazuh.manager wazuh.dashboard bridge

status:
	docker compose ps
