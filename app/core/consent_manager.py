"""Minimal consent manager shim for tests."""

def get_consent_manager():
    class _CM:
        def has_consented(self, user_id: str) -> bool:
            return True

        def record_consent(self, user_id: str) -> None:
            pass

    return _CM()

__all__ = ["get_consent_manager"]
