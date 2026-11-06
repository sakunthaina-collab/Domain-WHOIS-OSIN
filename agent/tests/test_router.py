from __future__ import annotations
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.registry import Profile, Registry
from core.router import Router, filter_by_category


@pytest.fixture
def registry():
    return Registry(AGENT_DIR / "skills")


def test_thai_query_routes_to_google_maps_scraper(registry):
    growth_profile = Profile.from_yaml(AGENT_DIR / "profiles" / "growth.yaml")
    router = Router(registry, allowed_categories=growth_profile.categories)
    hits = router.route("หาเบอร์โทรของร้านอาหารในเชียงใหม่", k=5)
    assert hits[0] == "google-maps-scraper"


def test_chinese_query_routes_to_phone_email_osint(registry):
    inv_profile = Profile.from_yaml(AGENT_DIR / "profiles" / "investigator.yaml")
    router = Router(registry, allowed_categories=inv_profile.categories)
    hits = router.route("追踪电话号码和关联账户", k=5)
    assert hits[0] == "phone-email-osint"


def test_investigator_excludes_scraping_and_unconfirmed(registry):
    inv_profile = Profile.from_yaml(AGENT_DIR / "profiles" / "investigator.yaml")
    router = Router(registry, allowed_categories=inv_profile.categories)
    hits = router.route(
        "ตรวจสอบเบอร์ +66942638165 และเครือข่ายที่เชื่อมโยง จัดทำสำนวนส่งตำรวจ",
        k=6,
        exclude_unconfirmed=inv_profile.guardrails.get("require_confirm", []),
    )
    assert "google-maps-scraper" not in hits
    assert "phone-email-osint" in hits
    assert "case-dossier-exporter" in hits
    assert filter_by_category(hits, registry, inv_profile.categories) == hits
