from datetime import datetime, timezone


def run(target_alias: str = "予安 / 小白", channel: str = "@bv92111", **kwargs):
    return {
        "ok": True,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "monitored_channels": ["@bv92111", "@huai9211", "@df52iii", "@tang20010101"],
        "primary_channel": channel,
        "target_alias": target_alias,
        "shift_window_tw": "13:00 UTC+8 (12:00 UTC+7 TH)",
        "identity_disambiguation": {
            "予安 (Yu-An)": "163/52/D (Confirmed distinct individual)",
            "箏箏 (Zheng-Zheng)": "162/47/D (Confirmed distinct individual)",
            "小白 (Xiao Bai)": "Recent Telegram display-name mutation observed at 00:35 UTC+7",
        },
    }
