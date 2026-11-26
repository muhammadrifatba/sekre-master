"""
test_sekre_adapter.py — Unit and API tests for the Approval Gate Adapter
(`sekre_results` + `sekre_actions` + `sekre_audit` + `customer_master_profiles` v3).
"""
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import sekre_adapter  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def _sample_profile(category: str = "customer") -> dict:
    return {
        "master_id": "mp_bkt_hendra_p",
        "contact_id": "c_hendra_p",
        "full_name": "Hendra Pratama",
        "role_title": "Direktur Operasional",
        "category": category,
        "personalization_level": "timing_only" if category == "peer" else "full",
        "org_id": "org_bkt",
        "org_name": "PT Borneo Karya Tambang",
        "city": "Samarinda",
        "timezone": "Asia/Makassar",
        "tz_label": "WITA",
        "work_hours_local": "08:00-17:00",
        "email": "hendra.pratama@borneo-tambang.example",
        "phone_wa": "+628000001002",
        "character_style": "Driver",
        "churn_risk_level": "high",
        "open_complaints": [{"text": "HD785-7 breakdown 5 hari di Pit 3 Samarinda"}],
        "relationship_health": {
            "open_promises": [
                {"owner": "us", "item": "Kirim brosur TCO PC200-8M0", "due_date": "2026-11-24", "status": "overdue"}
            ]
        },
        "agent_brief": "Brief Customer — Hendra Pratama (Driver, WITA, churn high).",
    }


class TestSekreAdapterPure:
    def test_awaiting_approval_enriches_draft_and_customer_context(self):
        now = datetime(2026, 11, 25, 11, 0, tzinfo=timezone.utc)  # 19:00 WITA (after-hours)
        result_row = {
            "request_id": "req_001",
            "owner_key": "owner_demo",
            "run_id": "run_001",
            "status": "awaiting_approval",
            "source_summary": "Follow-up komplain HD785-7 & penawaran PC200-8M0",
            "source_refs": ["whatsapp:wa_001"],
            "payload_hash": "abc123",
            "payload": {
                "todo_items": [{"id": "todo-1", "title": "Telepon Service Head"}],
                "injection_findings": [{"id": "inj-1", "excerpt": "Ignore previous rules"}],
                "message_drafts": [
                    {
                        "draft_id": "draft_wa_01",
                        "channel": "wa",
                        "target_id": "c_hendra_p",
                        "subject": "",
                        "body_draft": "Selamat pagi Pak Hendra",
                    }
                ],
            },
            "created_at": now,
            "updated_at": now,
        }
        action_rows = [
            {
                "action_id": "act_001",
                "request_id": "req_001",
                "action_type": "wa_handoff",
                "target_type": "message_draft",
                "target_id": "c_hendra_p",
                "status": "awaiting_approval",
                "idempotency_key": "req_001:wa_handoff:01",
                "approval_hash": "",
                "risk_tier": "high",
                "payload_hash": "def456",
                "payload": {
                    "draft_id": "draft_wa_01",
                    "channel": "wa",
                    "recipient_name": "Hendra Pratama",
                    "subject": "",
                    "body_draft": "Selamat pagi Pak Hendra",
                },
            }
        ]
        prof = _sample_profile("customer")
        card = sekre_adapter.build_request_card(
            result_row=result_row,
            actions_rows=action_rows,
            profiles_by_cid={"c_hendra_p": prof},
            org_news_by_org={"org_bkt": [{"headline": "PT BKT wins new pit contract", "date": "2026-11-18"}]},
            all_profiles=[prof],
            now_utc=now,
        )

        assert card["interrupt"]["type"] == "APPROVAL"
        assert card["interrupt"]["approval_hash"] == "abc123"
        actions = card["state"]["plan"]["actions"]
        assert len(actions) == 1
        act = actions[0]
        assert act["channel"] == "whatsapp"
        assert act["what"]["subject"] == ""
        assert act["what"]["body_draft"] == "Selamat pagi Pak Hendra"
        assert act["who"]["category"] == "customer"
        assert act["who"]["phone"] == "+628000001002"
        assert act["who"]["org_name"] == "PT Borneo Karya Tambang"
        assert act["wa_handoff_link"].startswith("https://wa.me/628000001002")
        assert act["when"]["rule_applied"] == "BR-04_AFTER_HOURS_DEFER"

        ctx = card["state"]["customer_context"]["act_001"]
        assert ctx["character_style"] == "Driver"
        assert ctx["churn_risk_level"] == "high"
        assert "Brief Customer" in ctx["agent_brief"]
        assert len(ctx["relationship_signals"]) == 1
        assert ctx["commitments"][0]["status"] == "overdue"
        assert ctx["company_news"][0]["headline"] == "PT BKT wins new pit contract"
        assert len(card["state"]["injection_flags"]) == 1

    def test_needs_clarify_with_empty_actions_populates_candidates(self):
        now = datetime(2026, 11, 25, 9, 0, tzinfo=timezone.utc)
        prof = _sample_profile("customer")
        result_row = {
            "request_id": "req_clarify_01",
            "owner_key": "owner_demo",
            "status": "needs_clarify",
            "source_summary": "Email menyebut Hendra tanpa alamat.",
            "source_refs": ["outlook_sekre:001"],
            "payload_hash": "hash_c",
            "payload": {
                "ambiguities": [
                    {
                        "id": "amb-1",
                        "field": "recipient",
                        "description": "Hendra Pratama belum ter-resolve.",
                        "clarification_question": "Kontak Hendra mana yang dimaksud?",
                    }
                ],
                "message_drafts": [],
            },
            "created_at": now,
            "updated_at": now,
        }
        card = sekre_adapter.build_request_card(
            result_row=result_row,
            actions_rows=[],
            profiles_by_cid={"c_hendra_p": prof},
            all_profiles=[prof],
            now_utc=now,
        )
        assert card["interrupt"]["type"] == "CLARIFY"
        assert card["state"]["plan"]["actions"] == []
        cands = card["interrupt"]["ambiguities"][0]["candidates"]
        assert len(cands) == 1
        assert cands[0]["contact_id"] == "c_hendra_p"
        assert len(cands[0]["proposed_friday_slots"]) == 2

    def test_tr10_peer_context_strips_private_data(self):
        peer_prof = _sample_profile("peer")
        ctx = sekre_adapter.build_customer_context_snapshot(peer_prof, org_news=[{"headline": "Internal"}])
        assert ctx["category"] == "peer"
        assert ctx["personalization_level"] == "timing_only"
        assert ctx["relationship_signals"] == []
        assert ctx["commitments"] == []
        assert ctx["company_news"] == []
        assert ctx["agent_brief"] == ""

    def test_verify_sekre_audit_chain(self):
        ev1 = {"event_id": "e1", "prev_hash": "0" * 64, "curr_hash": "h1"}
        ev2 = {"event_id": "e2", "prev_hash": "h1", "curr_hash": "h2"}
        ev3 = {"event_id": "e3", "prev_hash": "h2", "curr_hash": "h3"}
        ok = sekre_adapter.verify_sekre_audit_chain([ev1, ev2, ev3])
        assert ok["valid"] is True
        assert ok["total_events"] == 3
        assert ok["head_hash"] == "h3"
        assert ok["reason"] == ""
        assert ok["message"]

        # Same-timestamp events returned out of order should still validate cleanly
        reordered = sekre_adapter.verify_sekre_audit_chain([ev1, ev3, ev2])
        assert reordered["valid"] is True

        ev2_bad = {"event_id": "e2", "prev_hash": "WRONG", "curr_hash": "h2"}
        bad = sekre_adapter.verify_sekre_audit_chain([ev1, ev2_bad])
        assert bad["valid"] is False
        assert len(bad["breaks"]) == 1
        assert "Chain break" in bad["reason"]
        assert "Chain break" in bad["message"]


class TestSekreAdapterAPIAuth:
    def test_v1_endpoints_require_jwt(self):
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/requests").status_code == 401
        assert client.get("/api/v1/requests/latest").status_code == 401
        assert client.get("/api/v1/requests/req_1").status_code == 401
        assert client.get("/api/v1/contacts").status_code == 401
        assert client.get("/api/v1/outbox").status_code == 401
        assert client.post("/api/v1/outbox/act_1/undo").status_code == 401
        assert client.post("/api/v1/outbox/act_1/cancel").status_code == 401
        assert client.post("/api/v1/outbox/cancel", json={"action_id": "act_1"}).status_code == 401
        assert client.get("/api/v1/audit/verify").status_code == 401
        assert client.get("/api/v1/crm-complaints").status_code == 401
        assert client.get("/api/v1/order-followups").status_code == 401
        assert client.post("/api/v1/requests/req_1/approve", json={"action_id": "a1"}).status_code == 401

    def test_v1_requests_with_valid_jwt(self):
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "list_approval_requests",
            return_value={"success": True, "owner_key": "owner_demo", "count": 0, "requests": []},
        ):
            res = client.get("/api/v1/requests", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            assert res.json()["success"] is True

    def test_v1_approve_checks_send_external_permission(self):
        token = create_access_token("owner_readonly", "Viewer", permissions=["ingest"])
        res = client.post(
            "/api/v1/requests/req_1/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"action_id": "act_1", "decision": "approve"},
        )
        assert res.status_code == 403

    def test_cors_preflight_allows_sekre_web_id(self):
        for origin in ("https://sekre-v3.web.id", "https://www.sekre-v3.web.id"):
            res = client.options(
                "/auth/login",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type,authorization",
                },
            )
            assert res.status_code == 200
            assert res.headers.get("access-control-allow-origin") == origin

    def test_v1_order_followups_with_valid_jwt(self):
        token = create_access_token("owner_rifat", "Rifat")
        sample = {
            "success": True,
            "owner_key": "owner_demo",
            "run_id": "run-123",
            "count": 1,
            "items": [
                {
                    "order_draft_id": "ord-001",
                    "nama_pemesan": "Hendra Pratama",
                    "nama_customer": "PT Borneo Karya Tambang",
                    "po_reference": "PO-2026-001",
                    "due_date": "2026-12-01",
                    "so_id": "SO-1001",
                    "so_status": "open",
                    "billing_status": "unbilled",
                    "items": [{"item": "PC200-8M0", "qty": 4, "unit": "unit"}],
                }
            ],
        }
        with patch.object(sekre_adapter, "list_order_followups", return_value=sample):
            res = client.get("/api/v1/order-followups", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            data = res.json()
            assert data["count"] == 1
            assert data["items"][0]["so_id"] == "SO-1001"

    def test_v1_approve_order_followup_auth_and_happy_path(self):
        # Requires JWT
        assert client.post("/api/v1/order-followups/approve", json={"order_draft_id": "ord-1"}).status_code == 401

        # Requires permission
        ro_token = create_access_token("owner_ro", "Viewer", permissions=["ingest"])
        assert (
            client.post(
                "/api/v1/order-followups/approve",
                headers={"Authorization": f"Bearer {ro_token}"},
                json={"order_draft_id": "ord-1", "decision": "approve", "items": [{"item": "PC200", "qty": 1, "unit": "unit"}]},
            ).status_code
            == 403
        )

        # Happy path
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "approve_order_followup",
            return_value={
                "success": True,
                "approved_order": {"approved_order_id": "ord_apr_123", "decision": "approved", "so_status": "processing"},
                "audit_event_id": "evt_123",
            },
        ):
            res = client.post(
                "/api/v1/order-followups/approve",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "order_draft_id": "ord-001",
                    "so_id": "SO-1001",
                    "nama_customer": "PT Borneo Karya Tambang",
                    "decision": "approve",
                    "items": [{"item": "PC200-8M0", "qty": 4, "unit": "unit"}],
                },
            )
            assert res.status_code == 200
            assert res.json()["approved_order"]["approved_order_id"] == "ord_apr_123"

    def test_v1_outbox_cancel_endpoints(self):
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "cancel_outbox_action",
            return_value={
                "success": True,
                "cancelled": True,
                "outbox_id": "obx_act_1",
                "action_id": "act_1",
                "request_id": "req_1",
                "status": "undone",
                "action_status": "awaiting_approval",
            },
        ) as mock_cancel:
            res0 = client.post("/api/v1/outbox/act_1/undo", headers={"Authorization": f"Bearer {token}"})
            assert res0.status_code == 200
            assert res0.json()["status"] == "undone"

            res1 = client.post("/api/v1/outbox/act_1/cancel", headers={"Authorization": f"Bearer {token}"})
            assert res1.status_code == 200
            assert res1.json()["cancelled"] is True

            res2 = client.post(
                "/api/v1/outbox/cancel",
                headers={"Authorization": f"Bearer {token}"},
                json={"outbox_id": "obx_act_1"},
            )
            assert res2.status_code == 200
            assert mock_cancel.call_count == 3

    def test_v1_get_request_and_contacts(self):
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "get_approval_request_by_id",
            return_value={"request_id": "req_1", "status": "awaiting_approval"},
        ):
            res = client.get("/api/v1/requests/req_1", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            assert res.json()["request_id"] == "req_1"

        with patch.object(
            sekre_adapter,
            "list_contacts",
            return_value={"success": True, "count": 1, "contacts": [{"contact_id": "c_andi", "email": "andi.e2e@example.test"}]},
        ):
            res_c = client.get("/api/v1/contacts", headers={"Authorization": f"Bearer {token}"})
            assert res_c.status_code == 200
            assert res_c.json()["contacts"][0]["email"] == "andi.e2e@example.test"

    def test_v1_outbox_cancel_expired_returns_409(self):
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "cancel_outbox_action",
            return_value={
                "success": False,
                "status_code": 409,
                "error": "Waktu tunda pengaman 60 detik sudah habis; pengiriman tidak dapat dibatalkan.",
            },
        ):
            res = client.post("/api/v1/outbox/act_1/cancel", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 409

    def test_v1_approve_rejects_missing_email_400(self):
        token = create_access_token("owner_rifat", "Rifat")
        with patch.object(
            sekre_adapter,
            "approve_or_reject_action",
            return_value={
                "success": False,
                "status_code": 400,
                "error": "Alamat email penerima belum tersedia.",
            },
        ):
            res = client.post(
                "/api/v1/requests/req_1/approve",
                headers={"Authorization": f"Bearer {token}"},
                json={"action_id": "act_1", "decision": "approve"},
            )
            assert res.status_code == 400
            assert "email" in res.json()["detail"].lower()
