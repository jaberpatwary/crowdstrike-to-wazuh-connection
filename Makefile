.DEFAULT_GOAL := help

# The Wazuh stack is kept in the sibling news-portal-wazuh project.
WAZUH_DIR ?= ../../wazuh/news-portal-wazuh
WAZUH_COMPOSE = docker compose --project-directory "$(WAZUH_DIR)" --env-file "$(WAZUH_DIR)/.env.wazuh" -f "$(WAZUH_DIR)/docker-compose.wazuh.yml"

.PHONY: help start logs status
help:
	@echo Targets: start, logs, status

# Start Wazuh first (network/log volume), then build and start the bridge + Postgres.
start:
	$(WAZUH_COMPOSE) up -d
	docker compose up -d --build

logs:
	docker compose logs -f bridge

status:
	$(WAZUH_COMPOSE) ps
	docker compose ps
