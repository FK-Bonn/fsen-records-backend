#! /usr/bin/env python3

import json
import sqlite3
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, date, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

IGNORED_FS_IDS = ['Altkatholisches-Seminar', 'Griechische-und-Lateinische-Philologie']

DB_PATH = "/data/db/data.db"
OUTBOX_PATH = Path("/data/mails/outbox")

PERMISSION_NAMES = {
    "read_files": "👀 Dateien anzeigen",
    "read_permissions": "👀 Berechtigungen anzeigen",
    "write_permissions": "✏️ Berechtigungen ändern",
    "read_public_data": "👀 FS-Daten anzeigen",
    "write_public_data": "✏️ FS-Daten ändern",
    "read_protected_data": "👀 geschützte FS-Daten anzeigen",
    "write_protected_data": "️✏️ geschützte FS-Daten ändern",
    "submit_payout_request": "️✏️ Anträge stellen",
    "upload_proceedings": "📃 Protokolle hochladen",
    "delete_proceedings": "🚮️ Protokolle löschen",
    "upload_documents": "⬆️ Dokumente hochladen",
    "locked": "🔒 Rechte-Bearbeitung nur durch FSK",
}


@dataclass
class AllData:
    payout_requests: list[dict]
    elections: list[dict]
    financial_year_starts: dict[str, str]
    financial_year_overrides: dict[str, dict]
    permissions: list[dict]
    requestable_afsg_periods: dict[str, dict]
    fs_data: dict[str, dict]


HandlerFunction = Callable[[str, dict, AllData], list[dict]]


def get_emails_for_purpose(data, purpose) -> list[str]:
    emails = []
    for item in data["email_addresses"]:
        if purpose in item["usages"]:
            emails.append(item["address"])
    return emails


def get_templates() -> list[dict]:
    templates = []
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    res = db.execute("""SELECT template_id, meta, subject, body
                        FROM email_templates
                        WHERE id IN (SELECT max(id) FROM email_templates GROUP BY template_id)
                        ORDER BY template_id ASC""")
    for line in res.fetchall():
        templates.append(
            {
                "template_id": line["template_id"],
                "meta": json.loads(line["meta"]),
                "subject": line["subject"],
                "body": line["body"],
            }
        )
    return templates


def get_payout_requests() -> list[dict]:
    payout_requests = []
    for type_ in ["afsg", "bfsg", "vorankuendigung"]:
        response = requests.get(f"https://fsen.datendrehschei.be/api/v1/payout-request/{type_}")
        response.raise_for_status()
        payout_requests.extend(response.json())
    return payout_requests


def get_elections() -> list[dict]:
    response = requests.get("https://fsen.datendrehschei.be/api/v1/elections/")
    response.raise_for_status()
    return response.json()


def get_financial_year_starts() -> dict[str, str]:
    finanical_year_starts = {}
    response = requests.get("https://fsen.datendrehschei.be/api/v1/data")
    response.raise_for_status()
    data = response.json()
    today = get_today()
    for fs, fs_data in data.items():
        start = fs_data["base"]["data"]["financial_year_start"]
        day = start[0:2]
        month = start[3:5]
        finanical_year_starts[fs] = f"{today.year}-{month}-{day}"
        override = fs_data["base"]["data"]["financial_year_override"]
        if override:
            finanical_year_starts[fs] = override["current"]["date_start"]
    return finanical_year_starts


def get_financial_year_overrides() -> dict[str, dict]:
    finanical_year_overrides = {}
    response = requests.get("https://fsen.datendrehschei.be/api/v1/data")
    response.raise_for_status()
    data = response.json()
    for fs, fs_data in data.items():
        finanical_year_overrides[fs] = fs_data["base"]["data"]["financial_year_override"]
    return finanical_year_overrides


def get_permissions() -> list[dict]:
    permissions = []
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    res = db.execute("""SELECT 
                            u.username as username,
                            u.full_name as full_name,
                            fs,
                            read_permissions,
                            write_permissions, 
                            read_files, 
                            read_public_data, 
                            write_public_data,
                            read_protected_data,
                            write_protected_data,
                            submit_payout_request,
                            upload_proceedings,
                            delete_proceedings,
                            upload_documents,
                            locked
                        FROM permissions p JOIN users u on p.user = u.username
                        ORDER BY fs, username ASC""")
    for line in res.fetchall():
        permissions.append(
            {
                "fs_id": line["fs"],
                "username": line["username"],
                "full_name": line["full_name"],
                "permissions": {
                    "read_permissions": line["read_permissions"],
                    "write_permissions": line["write_permissions"],
                    "read_files": line["read_files"],
                    "read_public_data": line["read_public_data"],
                    "write_public_data": line["write_public_data"],
                    "read_protected_data": line["read_protected_data"],
                    "write_protected_data": line["write_protected_data"],
                    "submit_payout_request": line["submit_payout_request"],
                    "upload_proceedings": line["upload_proceedings"],
                    "locked": line["locked"],
                },
            }
        )
    return permissions


def get_requestable_afsg_periods() -> dict:
    today = get_today()
    legacy = {
        "2025-SoSe": "2026-09-30",
        "2025-WiSe": "2027-03-31",
        "2026-SoSe": "2027-09-30",
        "2026-HHJ": "2028-06-30",
    }
    periods = {}
    for period_id, end_date in legacy.items():
        if today.isoformat() <= end_date:
            periods[period_id] = end_date
    if today.month > 6:
        periods[f"{today.year}-HHJ"] = f"{today.year + 1}-06-30"
    else:
        periods[f"{today.year - 1}-HHJ"] = f"{today.year + 1}-06-30"
    return periods


def get_fs_data() -> dict[str, dict[str, list[str]]]:
    fs_data = {}
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    res = db.execute("""SELECT fs, data
                        FROM protected_fs_data
                        WHERE id IN (SELECT max(id) FROM protected_fs_data WHERE approved=1 GROUP BY fs)
                        ORDER BY fs ASC""")
    for line in res.fetchall():
        if line["fs"] in IGNORED_FS_IDS:
            continue
        data = json.loads(line["data"])
        fs_data[line["fs"]] = {
            purpose: get_emails_for_purpose(data, purpose) for purpose in ["finanzen", "kontakt", "fsl"]
        }
    res = db.execute("""SELECT fs, data
                        FROM base_fs_data
                        WHERE id IN (SELECT max(id) FROM base_fs_data WHERE approved=1 GROUP BY fs)
                        ORDER BY fs ASC""")
    for line in res.fetchall():
        if line["fs"] in IGNORED_FS_IDS:
            continue
        data = json.loads(line["data"])
        fs_data[line["fs"]]["name"] = data["name"]

    return fs_data


def render(template: dict, items: dict) -> tuple[str, str]:
    subject = template["subject"].format(**items)
    body = template["body"].format(**items)
    return subject, body


def payout_request_expiry_date_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    emails = []
    today = get_today()
    warn_date = today + timedelta(days=template["meta"].get("days_before", 0))
    payout_requests_for_fs = [p for p in all_data.payout_requests if p["fs"] == fs_id]
    for payout_request in payout_requests_for_fs:
        if payout_request["completion_deadline"] == warn_date.isoformat():
            fs_name = all_data.fs_data[fs_id]["name"]
            recipients = get_recipients(all_data, fs_id, template)
            request_id = payout_request["request_id"]
            subject, body = render(
                template, dict(request_id=request_id, fs_id=fs_id, fs_name=fs_name, completion_deadline=warn_date)
            )
            emails.append(
                mail(
                    recipients=recipients,
                    subject=subject,
                    body=body,
                    template_id=template["template_id"],
                )
            )
    return emails


def election_due_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    today = get_today()
    if 4 <= today.month <= 9:
        next_semester_start = date(today.year, 10, 1)
    elif 4 > today.month:
        next_semester_start = date(today.year, 4, 1)
    else:
        next_semester_start = date(today.year + 1, 4, 1)
    send_date = next_semester_start - timedelta(days=template["meta"].get("days_before", 1))
    if send_date.isoformat() != today.isoformat():
        return []
    search_period_start = next_semester_start - timedelta(days=183)
    elections_for_fs = [e for e in all_data.elections if e["fs"] == fs_id]
    for election in elections_for_fs:
        if search_period_start.isoformat() < election["last_election_day"] < next_semester_start.isoformat():
            return []
    fs_name = all_data.fs_data[fs_id]["name"]
    recipients = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_name=fs_name))
    return [
        mail(
            recipients=recipients,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def financial_year_start_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    today = get_today()
    check_date = today + timedelta(days=template["meta"].get("days_before", 0))
    financial_year_start = all_data.financial_year_starts[fs_id]
    if check_date.isoformat() != financial_year_start:
        return []
    fs_name = all_data.fs_data[fs_id]["name"]
    recipients = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_id=fs_id, fs_name=fs_name, financial_year_start=financial_year_start))
    return [
        mail(
            recipients=recipients,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def financial_year_overrides_are_out_of_date_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    override = all_data.financial_year_overrides[fs_id]
    if not override:
        return []
    today = get_today().isoformat()
    if override["current"]["date_start"] <= today <= override["current"]["date_end"]:
        return []
    fs_name = all_data.fs_data[fs_id]["name"]
    recipients = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_name=fs_name, fs_id=fs_id))
    return [
        mail(
            recipients=recipients,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def permissions_reminder_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    permissions_for_fs = [p for p in all_data.permissions if p["fs_id"] == fs_id]
    permissions = format_permissions(permissions_for_fs)
    fs_name = all_data.fs_data[fs_id]["name"]
    to_items = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_name=fs_name, fs_id=fs_id, permissions=permissions))

    return [
        mail(
            recipients=to_items,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def format_permissions(data: list[dict]):
    formatted = ""
    for permissions in sorted(data, key=lambda x: x["username"]):
        if permissions["username"] == "finanzreferat":
            continue
        if has_any_permission(permissions["permissions"]):
            formatted += f"» {permissions['full_name']} ({permissions['username']}):\n"
            for key, substitution in PERMISSION_NAMES.items():
                if permissions["permissions"].get(key, False):
                    formatted += f"  {substitution}\n"
            formatted += "\n"
    if formatted == "":
        return "_Niemand hat aktuell Berechtigungen_"
    return formatted


def has_any_permission(permissions: dict):
    for key, substitution in PERMISSION_NAMES.items():
        if permissions.get(key, False):
            return True
    return False


def deadline_reminder_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    today = get_today()
    current_financial_year = f"Haushaltsjahr {today.year - 1}/{today.year}"
    current_financial_year_id = f"{today.year - 1}-HHJ"
    if today.month > 6:
        current_financial_year = f"Haushaltsjahr {today.year}/{today.year + 1}"
        current_financial_year_id = f"{today.year}-HHJ"

    afsg_request_for_financial_year = [
        p for p in all_data.payout_requests if p["semester"] == current_financial_year_id and p["fs"] == fs_id
    ]
    if afsg_request_for_financial_year:
        return []

    fs_name = all_data.fs_data[fs_id]["name"]
    to_items = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_name=fs_name, fs_id=fs_id, current_financial_year=current_financial_year))

    return [
        mail(
            recipients=to_items,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def should_be_rendered(template: dict) -> bool:
    today = get_today()
    if template["meta"]["fixed_dates"]:
        for fixed_date in template["meta"]["fixed_dates"]:
            if fixed_date["month"] == today.month and fixed_date["day"] == today.day:
                return True
    if template["meta"]["frequency"]:
        if template["meta"]["frequency"] == "daily":
            return True
        if template["meta"]["frequency"] == "weekly":
            return today.weekday() == 0
        if template["meta"]["frequency"] == "monthly":
            return today.day == 1
    return False


def default_handler(fs_id: str, template: dict, all_data: AllData) -> list[dict]:
    fs_name = all_data.fs_data[fs_id]["name"]
    to_items = get_recipients(all_data, fs_id, template)
    subject, body = render(template, dict(fs_name=fs_name, fs_id=fs_id))

    return [
        mail(
            recipients=to_items,
            subject=subject,
            body=body,
            template_id=template["template_id"],
        )
    ]


def get_recipients(all_data: AllData, fs_id: str, template: dict) -> list[str]:
    to_items = []
    for target in template["meta"]["targets"]:
        if target.lower() == "fsk":
            to_items.append("fsen@asta.uni-bonn.de")
        else:
            to_items.extend(all_data.fs_data[fs_id][target])
    return sorted(set(to_items))


def render_template(fs_id: str, template: dict, all_data: AllData):
    if not should_be_rendered(template):
        return []

    handlers: dict[str, HandlerFunction] = {
        "payout_request_approaches_expiry_date": payout_request_expiry_date_handler,
        "payout_request_has_reached_expiry_date": payout_request_expiry_date_handler,
        "election_due": election_due_handler,
        "new_financial_year_approaching": financial_year_start_handler,
        "new_financial_year_has_started": financial_year_start_handler,
        "financial_year_overrides_are_out_of_date": financial_year_overrides_are_out_of_date_handler,
        "permissions_reminder": permissions_reminder_handler,
        "deadline_reminder": deadline_reminder_handler,
    }
    handler = handlers.get(template["template_id"], default_handler)
    return handler(fs_id, template, all_data)


def main():
    templates = get_templates()
    all_data = AllData(
        payout_requests=get_payout_requests(),
        elections=get_elections(),
        financial_year_starts=get_financial_year_starts(),
        financial_year_overrides=get_financial_year_overrides(),
        permissions=get_permissions(),
        requestable_afsg_periods=get_requestable_afsg_periods(),
        fs_data=get_fs_data(),
    )

    for template in templates:
        for fs_id in all_data.fs_data:
            emails = render_template(fs_id, template, all_data)
            for email in emails:
                today = get_today().isoformat()
                now = berlinnow().isoformat()
                uuid_ = str(uuid.uuid4())
                target = OUTBOX_PATH / f"{today}-{uuid_}.json"
                target.write_text(
                    json.dumps(
                        {
                            "to": email["to"],
                            "subject": email["subject"],
                            "body": email["body"],
                            "template_id": email["template_id"],
                            "created": now,
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )


def get_today() -> date:
    return berlinnow().date()


def berlinnow() -> datetime:
    if len(sys.argv) > 1:
        d = datetime.fromisoformat(sys.argv[1])
        d = d.replace(tzinfo=ZoneInfo("Europe/Berlin"))
        return d
    return datetime.now(tz=ZoneInfo("Europe/Berlin"))


def mail(recipients: list[str], subject: str, body: str, template_id: str) -> dict:
    return {
        "to": recipients,
        "subject": subject,
        "body": body,
        "template_id": template_id,
    }


if __name__ == "__main__":
    main()
