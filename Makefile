.PHONY: install lint fmt test migrations-check check

# Цели, которые зовут CI (.github/workflows/ci.yml) и проверки исполнителя
# (.agents/runner.yaml). Меняешь команду — меняй её здесь, а не в копиях.

install:
	uv sync --frozen

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check . --fix
	uv run ruff format .

# Тесты автономны: SQLite, фиктивный OIDC issuer; integration пропускаются без
# IAM_TEST_*. Дополнительные аргументы: make test PYTEST_ARGS="tests/test_people.py -x".
test:
	uv run pytest -q $(PYTEST_ARGS)

# Ровно одна голова alembic: параллельные ветки с миграциями дают вторую.
migrations-check:
	@heads=$$(uv run alembic heads | grep -c '(head)'); \
	if [ "$$heads" -ne 1 ]; then \
		echo "alembic: голов $$heads, нужна одна (uv run alembic heads)" >&2; \
		exit 1; \
	fi

check: lint test migrations-check
