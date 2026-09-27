"""Агенты, которыми владеет service account (scope `iam:agents`).

Пакет самодостаточен, как `pat`, `scim` и `channels`: свои схемы и роутер,
таблиц нет — агент это обычный Principal с владельцем. Точка интеграции в
`iam_service.app` — один `include_router`.
"""

from iam_service.agents.routes import create_agent_router

__all__ = ["create_agent_router"]
