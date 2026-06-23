# tests/conftest.py
# Mock google.auth.default globally for offline/local unit and integration tests.

import google.auth
import google.auth.credentials

class DummyCredentials(google.auth.credentials.Credentials):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = "dummy-token"
    def refresh(self, request):
        pass

def dummy_default(**kwargs):
    return DummyCredentials(), "dummy-project"

# Override default credentials resolver globally during testing
google.auth.default = dummy_default
