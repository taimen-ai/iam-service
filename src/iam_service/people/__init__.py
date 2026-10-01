"""Управление людьми без bootstrap-токена: scope `iam:people`.

Маршруты principals tenant'а принимают, кроме bootstrap-токена, access token
IAM человека со scope `iam:people`, выданный federation-входом.
"""

from iam_service.people.guard import (
    Caller,
    create_people_guard,
    is_people_admin,
    refuse,
    require_human_target,
)

__all__ = ["Caller", "create_people_guard", "is_people_admin", "refuse", "require_human_target"]
