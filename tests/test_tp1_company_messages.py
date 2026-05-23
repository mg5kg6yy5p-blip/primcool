"""TP-1b: company message posting + visibility."""
import sqlite3
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DB = str(_PROJECT_ROOT / "submissions.db")


def test_super_admin_can_post_company_message(client, admin_token):
    r = client.post(
        "/api/admin/company/messages",
        json={"title": "TP-1b test", "body": "hello team"},
        cookies={"pc_admin_session": admin_token},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    assert isinstance(body.get("id"), int)


def test_tech_can_read_active_messages(client, admin_token, tech_token):
    """Post a message as admin → tech sees it in the active list."""
    post = client.post(
        "/api/admin/company/messages",
        json={"title": "TP-1b tech-visible", "body": "Visible to all"},
        cookies={"pc_admin_session": admin_token},
    )
    assert post.status_code == 200
    new_id = post.json()["id"]
    r = client.get(
        "/api/company/messages?limit=50",
        cookies={"pc_tech_session": tech_token},
    )
    assert r.status_code == 200, r.text
    rows = r.json()
    assert any(m.get("id") == new_id for m in rows)


def test_non_super_admin_cannot_post_company_message(client, supervisor_token):
    r = client.post(
        "/api/admin/company/messages",
        json={"title": "blocked", "body": "should 403"},
        cookies={"pc_admin_session": supervisor_token},
    )
    assert r.status_code == 403
