from core.case_id import validate_case_id


def run(case_id: str, **kwargs):
    case_id = validate_case_id(case_id)
    return {"ok": True, "case_id": case_id, "mode": "passive_abuse_report_package_prepared"}
