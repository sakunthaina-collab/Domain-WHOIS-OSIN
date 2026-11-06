import hashlib
import pathlib
from datetime import datetime, timezone
from core.case_id import validate_case_id


def run(case_id: str, languages: list[str] | None = None, **kwargs):
    case_id = validate_case_id(case_id)
    languages = languages or ["th", "zh-TW"]
    out_dir = pathlib.Path("artifacts") / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()

    dossier_md = f"""# สำนวนพยานหลักฐานดิจิทัล / 數位鑑識證據卷宗 ({case_id})
- **Timestamp (UTC):** `{ts}`
- **Jurisdiction Compliance:** พ.ร.บ. ป้องกันและปราบปรามการค้ามนุษย์ พ.ศ. 2551 & 臺灣人口販運防制法 / 刑事訴訟法
- **Languages:** {", ".join(languages)}
- **Location Reference:** 新北市中和區自立路147–149號 (ใกล้ไปรษณีย์ซิ่วซาน / 秀山郵局)
- **Verified Entities:** `予安` (163/52/D), `箏箏` (162/47/D), Telegram alias `小白`
"""
    md_path = out_dir / "004_case-dossier-exporter.md"
    md_path.write_text(dossier_md, encoding="utf-8")
    digest = hashlib.sha256(dossier_md.encode("utf-8")).hexdigest()
    return {
        "ok": True,
        "case_id": case_id,
        "dossier_path": str(md_path),
        "sha256_digest": digest,
        "timestamp_utc": ts,
    }
