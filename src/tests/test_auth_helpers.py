"""
Unit tests for the API-key token helpers added to contacts_reader.py and models.py.
No Flask test client is used here; ContactsData and GlobalData are constructed directly.
"""
import pytest
import warnings
from unittest.mock import MagicMock, patch

import os
import sys

topdir = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, topdir)

os.environ.setdefault('TESTING', 'True')

# Third-party deprecation from python-dateutil under Python 3.12;
# we do not control that dependency's internal datetime usage in these tests.
warnings.filterwarnings(
    "ignore",
    message=r"datetime\.datetime\.utcfromtimestamp\(\) is deprecated.*",
    category=DeprecationWarning,
    module=r"dateutil\.tz\.tz",
)

from webapp.common import token_to_apikeyhash
from webapp.contacts_reader import ContactsData, User
from webapp.models import GlobalData, CachedData


# ---------------------------------------------------------------------------
# Minimal YAML-dict helpers
# ---------------------------------------------------------------------------


def _make_user_yaml(full_name="Test User", email="test@example.com", api_key_hash=None):
    """Return a minimal user YAML dict, optionally with an APIKeyHash string."""
    data = {
        "FullName": full_name,
        "ContactInformation": {
            "PrimaryEmail": email,
        },
    }
    if api_key_hash is not None:
        data["ContactInformation"]["APIKeyHash"] = api_key_hash
    return data


def _make_contacts_data(*user_yamls):
    """Build a ContactsData from an iterable of (id, yaml_data) pairs."""
    raw = {str(i): yaml for i, yaml in enumerate(user_yamls)}
    return ContactsData(raw)


# ---------------------------------------------------------------------------
# ContactsData.get_api_keys() tests
# ---------------------------------------------------------------------------

class TestContactsDataGetApiKeys:

    def test_returns_hash_to_name_mapping(self):
        """get_api_keys() collects each user's APIKeyHash keyed to FullName."""
        hash_a = token_to_apikeyhash("tok-a")
        hash_b = token_to_apikeyhash("tok-b")
        cd = _make_contacts_data(
            _make_user_yaml(full_name="User A", api_key_hash=hash_a),
            _make_user_yaml(full_name="User B", api_key_hash=hash_b),
        )
        result = cd.get_api_keys()
        assert result == {hash_a: "User A", hash_b: "User B"}

    def test_skips_users_without_api_key_hash(self):
        """get_api_keys() does not raise when a user has no APIKeyHash key."""
        hash_x = token_to_apikeyhash("tok-x")
        cd = _make_contacts_data(
            _make_user_yaml(api_key_hash=hash_x),
            _make_user_yaml(),  # no APIKeyHash key
        )
        result = cd.get_api_keys()
        assert result == {hash_x: "Test User"}

    def test_returns_empty_dict_when_no_user_has_api_key_hash(self):
        """get_api_keys() returns {} when no user has any APIKeyHash value."""
        cd = _make_contacts_data(
            _make_user_yaml(),
            _make_user_yaml(),
        )
        result = cd.get_api_keys()
        assert result == {}

    @pytest.mark.parametrize("api_key_hash", [
        "abcd",
        "sha256:xyz",
        "sha256:" + "a" * 63,
        "sha256:" + "g" * 64,
    ])
    def test_rejects_invalid_api_key_hash_values(self, api_key_hash, caplog):
        import logging
        cd = _make_contacts_data(_make_user_yaml(api_key_hash=api_key_hash))
        with caplog.at_level(logging.WARNING, logger="webapp.contacts_reader"):
            result = cd.get_api_keys()
        assert result == {}
        assert "APIKeyHash" in caplog.text


# ---------------------------------------------------------------------------
# GlobalData.get_api_keys() tests
#
# We build a minimal GlobalData with CONTACT_DATA_DIR=None so it won't try
# to read any files, then override internal state and mocks as needed.
# ---------------------------------------------------------------------------

def _make_global_data():
    """Return a GlobalData instance configured for in-memory testing."""
    return GlobalData(config={"TOPOLOGY_DATA_DIR": ".", "CONTACT_DATA_DIR": None})


class TestGlobalDataGetApiKeys:

    def test_returns_a_dict(self):
        """get_api_keys() returns a dict of hash->owner when hashes exist."""
        gd = _make_global_data()
        token_hash = token_to_apikeyhash("tok-1")
        contacts = _make_contacts_data(_make_user_yaml(full_name="User 1", api_key_hash=token_hash))
        gd.get_contacts_data = MagicMock(return_value=contacts)
        result = gd.get_api_keys()
        assert isinstance(result, dict)
        assert result == {token_hash: "User 1"}

    def test_calls_get_contacts_data_when_cache_stale_and_stores_result(self):
        """get_api_keys() fetches contacts when cache is stale and caches the mapping."""
        gd = _make_global_data()
        # Ensure api_key_set exists and is stale (force_update=True by default)
        gd.api_key_set = CachedData()
        token_hash = token_to_apikeyhash("cached-tok")
        contacts = _make_contacts_data(_make_user_yaml(full_name="Cached User", api_key_hash=token_hash))
        gd.get_contacts_data = MagicMock(return_value=contacts)

        result = gd.get_api_keys()

        gd.get_contacts_data.assert_called_once()
        assert result is not None
        assert result[token_hash] == "Cached User"
        # Second call should use the cache and NOT call get_contacts_data again
        result2 = gd.get_api_keys()
        gd.get_contacts_data.assert_called_once()  # still just one call
        assert result2 == result

    def test_calls_try_again_on_get_api_keys_exception_and_returns_cached(self):
        """When get_api_keys() raises, try_again() is called and previous data is returned."""
        gd = _make_global_data()
        # Pre-populate the cache with previous data
        gd.api_key_set = CachedData()
        gd.api_key_set.update({token_to_apikeyhash("old-tok"): "Old User"})
        # Force the cache to be stale for the next call
        gd.api_key_set.force_update = True

        broken_contacts = MagicMock()
        broken_contacts.get_api_keys.side_effect = RuntimeError("boom")
        gd.get_contacts_data = MagicMock(return_value=broken_contacts)

        with patch.object(gd.api_key_set, 'try_again', wraps=gd.api_key_set.try_again) as mock_try_again:
            result = gd.get_api_keys()
            mock_try_again.assert_called_once()

        # Should return the previously cached data, not raise
        assert result == {token_to_apikeyhash("old-tok"): "Old User"}

    def test_returns_none_when_contacts_data_is_none_on_first_load(self):
        """get_api_keys() returns None (not an empty set) when get_contacts_data() returns None."""
        gd = _make_global_data()
        gd.api_key_set = CachedData()
        gd.get_contacts_data = MagicMock(return_value=None)

        result = gd.get_api_keys()

        assert result is None
