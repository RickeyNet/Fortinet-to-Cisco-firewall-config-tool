"""Tests for the FTD API code-review fixes.

Covers:
- Word-boundary transient-error matching (concurrency_utils)
- Shared pagination helpers with short pages (ftd_api_base)
- Deployment task polling (ftd_api_base)
- Phase-failure outcome computation (ftd_api_importer / ftd_api_cleanup)
- get_all_objects None-on-error and safety-cap handling (ftd_api_cleanup)
- Nested-group deletion retry passes (ftd_api_cleanup)
- Version-conflict PUT retry (ftd_api_importer)
- Interface no-change detection ignoring FDM meta fields (ftd_api_importer)
- EtherChannel creation failing when no members resolve (ftd_api_importer)
"""
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Path setup is also handled in tests/conftest.py; kept here as a fallback for
# running this module directly. Imports below must stay after this block.
ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "FortiGateToFTDTool"))

import concurrency_utils  # noqa: E402
import ftd_api_base  # noqa: E402
import ftd_api_cleanup  # noqa: E402
import ftd_api_importer  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Optional[Dict[str, Any]] = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text
        self.content = b"{}"

    def json(self) -> Dict[str, Any]:
        return self._json


class _ShortPageSession:
    """List endpoint that serves at most ``page_size`` items per request,
    regardless of the requested limit - exercises the offset-stride fix."""

    def __init__(self, items: List[Dict[str, Any]], page_size: int = 3) -> None:
        self._items = items
        self._page = page_size
        self.offsets: List[int] = []

    def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
        params = params or {}
        if "filter" in params:
            # Pretend the filter query is unsupported (returns nothing)
            return _FakeResponse(200, {"items": []})
        offset = int(params.get("offset", 0))
        self.offsets.append(offset)
        chunk = self._items[offset:offset + self._page]
        return _FakeResponse(200, {"items": chunk, "paging": {"count": len(self._items)}})


def _make_base_client(session: Any) -> ftd_api_base.FTDBaseClient:
    client = ftd_api_base.FTDBaseClient.__new__(ftd_api_base.FTDBaseClient)
    client.base_url = "https://fake/api/fdm/latest"
    client.session = session  # pyright: ignore[reportAttributeAccessIssue]
    return client


# ---------------------------------------------------------------------------
# M6: transient-error matcher
# ---------------------------------------------------------------------------

def test_transient_matcher_matches_status_codes_and_text() -> None:
    assert concurrency_utils.is_transient_api_error("HTTP 429 Too Many Requests")
    assert concurrency_utils.is_transient_api_error("HTTP 503 Service Unavailable")
    assert concurrency_utils.is_transient_api_error("HTTP 504 Gateway Timeout")
    assert concurrency_utils.is_transient_api_error("Locked (423)")
    assert concurrency_utils.is_transient_api_error("connection timeout")
    assert concurrency_utils.is_transient_api_error("rate limit exceeded")


def test_transient_matcher_ignores_codes_inside_object_names() -> None:
    # Digits embedded in larger numbers or identifiers must NOT retry
    assert not concurrency_utils.is_transient_api_error("Duplicate object name: net_4230_host")
    assert not concurrency_utils.is_transient_api_error("Object host_5031 already exists")
    assert not concurrency_utils.is_transient_api_error("value 14235 out of range")
    assert not concurrency_utils.is_transient_api_error(None)
    assert not concurrency_utils.is_transient_api_error("")


# ---------------------------------------------------------------------------
# M1/M2: shared pagination helpers
# ---------------------------------------------------------------------------

def test_get_paged_items_advances_by_actual_page_size() -> None:
    items = [{"name": f"obj{i}"} for i in range(10)]
    session = _ShortPageSession(items, page_size=3)
    client = _make_base_client(session)

    ok, result = client.get_paged_items("https://fake/x", page_limit=100)

    assert ok is True
    assert isinstance(result, list)
    assert [o["name"] for o in result] == [f"obj{i}" for i in range(10)]
    # Offsets advance by the actual page size (3), not the requested limit
    assert session.offsets == [0, 3, 6, 9]


def test_get_paged_items_returns_error_on_http_failure() -> None:
    class _ErrSession:
        def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
            return _FakeResponse(500)

    client = _make_base_client(_ErrSession())
    ok, result = client.get_paged_items("https://fake/x")
    assert ok is False
    assert "500" in str(result)


def test_find_object_by_name_finds_on_later_short_page() -> None:
    items = [{"name": f"obj{i}"} for i in range(7)] + [{"name": "target", "id": "t-1"}]
    session = _ShortPageSession(items, page_size=3)
    client = _make_base_client(session)

    found, obj = client.find_object_by_name("https://fake/x", "target")
    assert found is True
    assert isinstance(obj, dict) and obj["id"] == "t-1"


def test_find_object_by_name_match_fallback_and_not_found() -> None:
    items = [{"name": "a", "vlanId": 5}, {"name": "b", "vlanId": 7}]
    client = _make_base_client(_ShortPageSession(items, page_size=2))

    found, obj = client.find_object_by_name(
        "https://fake/x", "missing", match=lambda o: o.get("vlanId") == 7,
    )
    assert found is True
    assert isinstance(obj, dict) and obj["name"] == "b"

    found, err = client.find_object_by_name("https://fake/x", "missing")
    assert found is False
    assert "not found" in str(err).lower()


# ---------------------------------------------------------------------------
# I3: deployment polling
# ---------------------------------------------------------------------------

class _DeploySession:
    def __init__(self, states: List[str]) -> None:
        self._states = list(states)

    def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
        state = self._states.pop(0) if len(self._states) > 1 else self._states[0]
        return _FakeResponse(200, {"state": state})


def test_poll_deployment_success(monkeypatch: Any) -> None:
    monkeypatch.setattr(ftd_api_base.time, "sleep", lambda _s: None)
    client = _make_base_client(_DeploySession(["QUEUED", "DEPLOYING", "DEPLOYED"]))
    assert client.poll_deployment("task-1") is True


def test_poll_deployment_failure(monkeypatch: Any) -> None:
    monkeypatch.setattr(ftd_api_base.time, "sleep", lambda _s: None)
    client = _make_base_client(_DeploySession(["DEPLOYING", "FAILED"]))
    assert client.poll_deployment("task-1") is False


# ---------------------------------------------------------------------------
# H2: importer phase-failure outcome
# ---------------------------------------------------------------------------

def _make_importer_client() -> ftd_api_importer.FTDAPIClient:
    return ftd_api_importer.FTDAPIClient(host="dummy", username="u", password="p")


def test_importer_phase_failure_prevents_success_outcome() -> None:
    client = _make_importer_client()
    client.stats["address_objects_created"] = 3
    client.record_phase_failure("Service Objects")

    code, label = client.compute_outcome()
    assert code == 2
    assert label == "PARTIAL_FAILURE"


def test_importer_phase_failure_with_nothing_ok_is_all_failed() -> None:
    client = _make_importer_client()
    client.record_phase_failure("Address Objects")

    code, label = client.compute_outcome()
    assert code == 3
    assert label == "ALL_FAILED"


# ---------------------------------------------------------------------------
# H3/L4: cleanup listing failures
# ---------------------------------------------------------------------------

def _make_cleanup_client() -> ftd_api_cleanup.FTDBulkDelete:
    return ftd_api_cleanup.FTDBulkDelete(host="dummy", username="u", password="p")


def test_cleanup_get_all_objects_returns_none_on_http_error() -> None:
    class _ErrSession:
        def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
            return _FakeResponse(500)

    client = _make_cleanup_client()
    client.session = _ErrSession()  # pyright: ignore[reportAttributeAccessIssue]

    assert client.get_all_objects("/object/networks") is None


def test_cleanup_listing_failure_makes_phase_fail_not_success() -> None:
    class _ListingFails(ftd_api_cleanup.FTDBulkDelete):
        def get_all_objects(self, endpoint: str) -> Optional[List[Dict[str, Any]]]:
            return None

    client = _ListingFails(host="dummy", username="u", password="p")
    ok = client.delete_all_custom_objects("/object/networks", "Address Objects")
    assert ok is False

    # Empty list is genuinely "nothing to delete" and stays a success
    class _ListingEmpty(ftd_api_cleanup.FTDBulkDelete):
        def get_all_objects(self, endpoint: str) -> Optional[List[Dict[str, Any]]]:
            return []

    client2 = _ListingEmpty(host="dummy", username="u", password="p")
    assert client2.delete_all_custom_objects("/object/networks", "Address Objects") is True


def test_cleanup_safety_cap_marks_phase_failure() -> None:
    class _EndlessSession:
        def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
            offset = int((params or {}).get("offset", 0))
            items = [{"id": str(offset + i), "name": f"o{offset + i}"} for i in range(100)]
            return _FakeResponse(200, {"items": items, "paging": {"next": ["more"]}})

    client = _make_cleanup_client()
    client.session = _EndlessSession()  # pyright: ignore[reportAttributeAccessIssue]

    result = client.get_all_objects("/object/networks")
    assert result is not None
    assert len(result) >= 10000
    # Truncation must be recorded so the run does not report SUCCESS
    assert client.phase_failures
    code, _label = client.compute_outcome()
    assert code != 0


# ---------------------------------------------------------------------------
# M4: nested group deletion retry passes
# ---------------------------------------------------------------------------

def test_cleanup_nested_group_children_retried_after_parents(monkeypatch: Any) -> None:
    monkeypatch.setattr(concurrency_utils.time, "sleep", lambda _s: None)

    class _NestedGroupDelete(ftd_api_cleanup.FTDBulkDelete):
        def __init__(self) -> None:
            super().__init__(host="dummy", username="u", password="p")
            self.deleted_ids: set = set()

        def get_all_objects(self, endpoint: str) -> Optional[List[Dict[str, Any]]]:
            # Child listed first so the first pass tries (and fails) it
            # while the parent that references it still exists.
            return [
                {"id": "child", "name": "child-group", "isSystemDefined": False},
                {"id": "parent", "name": "parent-group", "isSystemDefined": False},
            ]

        def delete_object(self, endpoint: str, object_id: str) -> Tuple[bool, str]:
            if object_id == "child" and "parent" not in self.deleted_ids:
                return False, "Cannot delete the object because it is in use"
            self.deleted_ids.add(object_id)
            return True, ""

    client = _NestedGroupDelete()
    ok = client.delete_all_custom_objects(
        "/object/networkgroups", "Address Groups",
        dry_run=False, max_workers=1, max_attempts=1,
    )

    assert ok is True
    assert client.stats["deleted"] == 2
    assert client.stats["failed"] == 0
    assert client.deleted_ids == {"parent", "child"}


# ---------------------------------------------------------------------------
# M7: version-conflict PUT retry
# ---------------------------------------------------------------------------

def test_update_existing_object_retries_once_on_version_conflict() -> None:
    class _ConflictSession:
        def __init__(self) -> None:
            self.put_calls = 0
            self.get_calls = 0

        def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResponse:
            self.get_calls += 1
            version = "v1" if self.get_calls == 1 else "v2"
            return _FakeResponse(200, {"items": [{
                "name": "obj1", "id": "id-1", "version": version,
                "type": "networkobject", "value": "old",
            }]})

        def put(self, url: str, json: Any = None, timeout: Any = None) -> _FakeResponse:
            self.put_calls += 1
            if self.put_calls == 1:
                return _FakeResponse(422, {"error": {"messages": [{
                    "description": "The version provided does not match the current version of the object",
                }]}})
            return _FakeResponse(200, {"id": "id-1"})

    client = _make_importer_client()
    session = _ConflictSession()
    client.session = session  # pyright: ignore[reportAttributeAccessIssue]

    ok, msg = client._update_existing_object(
        "https://fake/object/networks", {"name": "obj1", "value": "new"}, "address_objects",
    )

    assert ok is True
    assert str(msg).startswith("UPDATED")
    assert session.put_calls == 2
    assert client.stats["address_objects_updated"] == 1
    assert client.stats["address_objects_failed"] == 0


# ---------------------------------------------------------------------------
# I1: interface no-change detection tolerates FDM meta fields
# ---------------------------------------------------------------------------

def test_physical_interface_matches_ignores_fdm_meta_in_ipv4() -> None:
    current = {
        "name": "outside", "mtu": 1500, "enabled": True,
        "ipv4": {
            "ipType": "STATIC", "type": "interfaceipv4",
            "ipAddress": {
                "ipAddress": "10.0.0.1", "netmask": "255.255.255.0",
                "type": "haipv4address", "version": "abc123", "id": "uuid-1",
            },
        },
    }
    desired = {
        "name": "outside", "mtu": 1500, "enabled": True,
        "ipv4": {
            "ipType": "STATIC",
            "ipAddress": {"ipAddress": "10.0.0.1", "netmask": "255.255.255.0"},
        },
    }
    assert ftd_api_importer.physical_interface_matches_json_config(current, desired) is True

    changed = {
        "name": "outside", "mtu": 1500, "enabled": True,
        "ipv4": {
            "ipType": "STATIC",
            "ipAddress": {"ipAddress": "10.0.0.2", "netmask": "255.255.255.0"},
        },
    }
    assert ftd_api_importer.physical_interface_matches_json_config(current, changed) is False


# ---------------------------------------------------------------------------
# M5: EtherChannel creation fails when no members resolve
# ---------------------------------------------------------------------------

def test_create_etherchannel_fails_when_no_members_resolve(monkeypatch: Any) -> None:
    client = _make_importer_client()
    monkeypatch.setattr(client, "get_physical_interface", lambda _hw: (False, "not found"))

    ok, msg = client.create_etherchannel({
        "name": "ec1", "hardwareName": "Port-channel1",
        "memberInterfaces": [{"hardwareName": "Ethernet1/1"}, {"hardwareName": "Ethernet1/2"}],
    })

    assert ok is False
    assert "member" in str(msg).lower()
    assert client.stats["etherchannels_failed"] == 1
