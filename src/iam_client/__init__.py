"""Reference-клиент IAM для локального harness (Codex, Claude Code и другие).

Пакет намеренно отделён от `iam_service`: он ставится рядом с плагином, ходит
по тем же публичным HTTP-контрактам, что и любой другой клиент, и не имеет
доступа к базе IAM.
"""

from iam_client.binding import Binding, load_binding
from iam_client.client import ExchangedToken, IamClient, Introspection
from iam_client.errors import BindingError, CredentialError, IamClientError, RemoteError
from iam_client.harness import HarnessSession, open_harness_session
from iam_client.store import CredentialStore, ResolvedCredential

__all__ = [
    "Binding",
    "BindingError",
    "CredentialError",
    "CredentialStore",
    "ExchangedToken",
    "HarnessSession",
    "IamClient",
    "IamClientError",
    "Introspection",
    "RemoteError",
    "ResolvedCredential",
    "load_binding",
    "open_harness_session",
]
