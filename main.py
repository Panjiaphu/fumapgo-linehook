import os
import hmac
import base64
import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

import requests
from flask import Flask, request, jsonify, abort

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
except Exception:
    service_account = None
    build = None
    MediaFileUpload = None


app = Flask(__name__)

LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_CHANNEL_ID = os.getenv("LINE_CHANNEL_ID", "")

FGO_BASE_URL = os.getenv("FGO_BASE_URL", "https://fumapgo.onrender.com").rstrip("/")
FGO_INTERNAL_SECRET = os.getenv("FGO_INTERNAL_SECRET", "")
FGO_ADMIN_LINE_USER_ID = os.getenv("FGO_ADMIN_LINE_USER_ID", "")
APP_MODE = os.getenv("APP_MODE", "fumapgo-linehook-step6-9")

GOOGLE_DRIVE_PROOF_FOLDER_ID = os.getenv("GOOGLE_DRIVE_PROOF_FOLDER_ID", "")
GOOGLE_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
GOOGLE_SERVICE_ACCOUNT_JSON_B64 = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_B64", "")

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_PROFILE_URL = "https://api.line.me/v2/bot/profile/{user_id}"
LINE_CONTENT_URL = "https://api-data.line.me/v2/bot/message/{message_id}/content"

SESSION_PATH = Path(os.getenv("PHOTO_SESSION_PATH", "/tmp/fumapgo_photo_sessions.json"))


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def json_ok(**kwargs):
    payload = {"ok": True, **kwargs}
    return jsonify(payload)


def json_fail(message: str, status_code: int = 400, **kwargs):
    payload = {"ok": False, "error": message, **kwargs}
    return jsonify(payload), status_code


def line_headers(content_type="application/json"):
    headers = {"Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def fgo_json_headers():
    return {
        "Content-Type": "application/json",
        "X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET,
    }


def verify_line_signature(body: bytes, signature: str) -> bool:
    if not LINE_CHANNEL_SECRET:
        return False

    digest = hmac.new(
        LINE_CHANNEL_SECRET.encode("utf-8"),
        body,
        hashlib.sha256,
    ).digest()

    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature or "")


def require_internal_secret():
    if not FGO_INTERNAL_SECRET:
        return False, "FGO_INTERNAL_SECRET not set"

    incoming = request.headers.get("X-FGO-INTERNAL-SECRET", "")

    if not incoming:
        return False, "X-FGO-INTERNAL-SECRET missing"

    if not hmac.compare_digest(incoming, FGO_INTERNAL_SECRET):
        return False, "invalid internal secret"

    return True, ""


def text_message(text: str):
    return {
        "type": "text",
        "text": str(text or "")[:5000],
    }


def image_message(image_url: str, preview_url: str = ""):
    preview_url = preview_url or image_url

    return {
        "type": "image",
        "originalContentUrl": image_url,
        "previewImageUrl": preview_url,
    }


def reply_message(reply_token: str, messages: list):
    if not LINE_CHANNEL_ACCESS_TOKEN or not reply_token:
        return {"ok": False, "error": "missing LINE token or reply token"}

    payload = {
        "replyToken": reply_token,
        "messages": messages[:5],
    }

    try:
        r = requests.post(
            LINE_REPLY_URL,
            headers=line_headers(),
            json=payload,
            timeout=15,
        )

        return {
            "ok": bool(r.ok),
            "status_code": r.status_code,
            "body": r.text[:500],
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


def push_message(to: str, messages: list):
    if not LINE_CHANNEL_ACCESS_TOKEN:
        return {"ok": False, "error": "LINE_CHANNEL_ACCESS_TOKEN not set"}

    if not to:
        return {"ok": False, "error": "target LINE user id missing"}

    payload = {
        "to": to,
        "messages": messages[:5],
    }

    try:
        r = requests.post(
            LINE_PUSH_URL,
            headers=line_headers(),
            json=payload,
            timeout=15,
        )

        body = {}
        if r.text:
            try:
                body = r.json()
            except Exception:
                body = {"raw": r.text[:500]}

        return {
            "ok": bool(r.ok),
            "status_code": r.status_code,
            "body": body,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


def push_text(to: str, text: str):
    return push_message(to, [text_message(text)])


def push_image(to: str, image_url: str, preview_url: str = "", text: str = ""):
    image_url = (image_url or "").strip()
    preview_url = (preview_url or image_url).strip()

    if not image_url:
        return {"ok": False, "error": "image_url missing"}

    if not image_url.startswith("https://"):
        return {
            "ok": False,
            "error": "LINE image URL must be public HTTPS",
            "image_url": image_url,
        }

    messages = []

    if text:
        messages.append(text_message(text))

    messages.append(image_message(image_url, preview_url))

    return push_message(to, messages)


def get_line_profile(user_id: str) -> dict:
    if not LINE_CHANNEL_ACCESS_TOKEN or not user_id:
        return {}

    try:
        url = LINE_PROFILE_URL.format(user_id=quote_plus(user_id))
        r = requests.get(
            url,
            headers=line_headers(content_type=None),
            timeout=10,
        )

        if not r.ok:
            return {}

        return r.json()

    except Exception:
        return {}


def fgo_post(path: str, payload: dict) -> dict:
    if not FGO_INTERNAL_SECRET:
        return {"ok": False, "error": "FGO_INTERNAL_SECRET not set"}

    try:
        r = requests.post(
            f"{FGO_BASE_URL}{path}",
            headers=fgo_json_headers(),
            json=payload,
            timeout=20,
        )

        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}

        return {
            "ok": bool(r.ok),
            "status_code": r.status_code,
            "body": body,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


def fgo_get(path: str, params=None) -> dict:
    if not FGO_INTERNAL_SECRET:
        return {"ok": False, "error": "FGO_INTERNAL_SECRET not set"}

    try:
        r = requests.get(
            f"{FGO_BASE_URL}{path}",
            headers={"X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET},
            params=params or {},
            timeout=20,
        )

        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}

        return {
            "ok": bool(r.ok),
            "status_code": r.status_code,
            "body": body,
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


def fgo_bind_line_user(payload: dict) -> dict:
    return fgo_post("/internal/line/bind", payload)


def fgo_resolve_line_user(line_user_id: str) -> dict:
    return fgo_get("/internal/line/resolve", {"line_user_id": line_user_id})


def manual_bind_url(user_id: str, role: str = "customer") -> str:
    return (
        f"{FGO_BASE_URL}/line/bind"
        f"?line_user_id={quote_plus(user_id or '')}"
        f"&role={quote_plus(role)}&view=mobile&lang=zh"
    )


def admin_approval_url() -> str:
    return f"{FGO_BASE_URL}/admin/line-bindings?status=PENDING_REVIEW&view=desktop&lang=zh"


def menu_text(user_id: str = ""):
    return (
        "FUMAP GO 信用外送｜LINE 中心\n\n"
        "【身份綁定】\n"
        "綁定客戶 0900000000\n"
        "綁定店家 STO-DEMO-ROAST\n"
        "綁定外送員 DRV-DEMO\n"
        "我的入口\n"
        "我的身份\n\n"
        "【交付證明】\n"
        "建議優先使用 Webapp 上傳照片。\n"
        "備用指令：photo FG-訂單碼\n"
        "備用完成：fu FG-訂單碼 ok 後四碼\n\n"
        "【一般入口】\n"
        f"店家入口：{FGO_BASE_URL}/store?view=mobile&lang=zh\n"
        f"外送員接單：{FGO_BASE_URL}/driver?view=mobile&lang=zh\n"
        f"顧客收貨：{FGO_BASE_URL}/customer?view=mobile&lang=zh\n"
        f"信用區塊：{FGO_BASE_URL}/block?view=mobile&lang=zh\n\n"
        f"你的 LINE User ID：{user_id}"
    )


def normalize_order_code(text: str) -> str:
    text = (text or "").strip().upper()
    m = re.search(r"(FG-\d{8}-[A-Z0-9]{6})", text)
    return m.group(1) if m else ""


def load_sessions() -> dict:
    try:
        if SESSION_PATH.exists():
            return json.loads(SESSION_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[SESSION_LOAD_ERROR] {e}", flush=True)

    return {}


def save_sessions(data: dict):
    try:
        SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
        SESSION_PATH.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        print(f"[SESSION_SAVE_ERROR] {e}", flush=True)


def set_photo_session(line_user_id: str, order_code: str, actor_role="DRIVER") -> dict:
    sessions = load_sessions()

    sessions[line_user_id] = {
        "order_code": order_code,
        "actor_role": actor_role,
        "created_at": now_iso(),
    }

    save_sessions(sessions)

    return sessions[line_user_id]


def get_photo_session(line_user_id: str) -> dict:
    return load_sessions().get(line_user_id, {})


def clear_photo_session(line_user_id: str):
    sessions = load_sessions()

    if line_user_id in sessions:
        sessions.pop(line_user_id)
        save_sessions(sessions)


def get_google_credentials():
    if service_account is None:
        raise RuntimeError("google-api-python-client/google-auth is not installed")

    raw = GOOGLE_SERVICE_ACCOUNT_JSON.strip()

    if not raw and GOOGLE_SERVICE_ACCOUNT_JSON_B64.strip():
        candidate = GOOGLE_SERVICE_ACCOUNT_JSON_B64.strip().strip('"').strip("'")

        if candidate.startswith("{"):
            raw = candidate
        else:
            raw = base64.b64decode(candidate).decode("utf-8")

    if not raw:
        raise RuntimeError("GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_JSON_B64 is not set")

    info = json.loads(raw)

    if "private_key" in info and "\\n" in info["private_key"]:
        info["private_key"] = info["private_key"].replace("\\n", "\n")

    scopes = ["https://www.googleapis.com/auth/drive.file"]

    return service_account.Credentials.from_service_account_info(
        info,
        scopes=scopes,
    )


def upload_to_google_drive(local_path: str, file_name: str, mime_type: str) -> dict:
    if not GOOGLE_DRIVE_PROOF_FOLDER_ID:
        return {
            "ok": False,
            "skipped": True,
            "error": "GOOGLE_DRIVE_PROOF_FOLDER_ID not set",
        }

    creds = get_google_credentials()
    service = build("drive", "v3", credentials=creds)

    metadata = {
        "name": file_name,
        "parents": [GOOGLE_DRIVE_PROOF_FOLDER_ID],
    }

    media = MediaFileUpload(
        local_path,
        mimetype=mime_type or "image/jpeg",
        resumable=False,
    )

    created = service.files().create(
        body=metadata,
        media_body=media,
        fields="id,name,webViewLink,webContentLink",
    ).execute()

    try:
        service.permissions().create(
            fileId=created["id"],
            body={"type": "anyone", "role": "reader"},
            fields="id",
        ).execute()
    except Exception as e:
        print(f"[GOOGLE_DRIVE_PERMISSION_WARNING] {e}", flush=True)

    file_id = created.get("id", "")

    return {
        "ok": True,
        "file_id": file_id,
        "name": created.get("name", file_name),
        "web_view_link": created.get("webViewLink", ""),
        "web_content_link": created.get("webContentLink", ""),
        "public_image_url": f"https://drive.google.com/uc?export=view&id={file_id}" if file_id else "",
    }


def download_line_content(message_id: str) -> dict:
    url = LINE_CONTENT_URL.format(message_id=message_id)

    r = requests.get(
        url,
        headers=line_headers(content_type=None),
        stream=True,
        timeout=30,
    )

    if not r.ok:
        return {
            "ok": False,
            "status_code": r.status_code,
            "error": r.text[:500],
        }

    content_type = r.headers.get("Content-Type", "image/jpeg")
    suffix = ".jpg"

    if "png" in content_type:
        suffix = ".png"
    elif "webp" in content_type:
        suffix = ".webp"
    elif "gif" in content_type:
        suffix = ".gif"

    fd, temp_path = tempfile.mkstemp(
        prefix="fgo_line_photo_",
        suffix=suffix,
    )

    size = 0
    sha = hashlib.sha256()

    with os.fdopen(fd, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 64):
            if not chunk:
                continue

            size += len(chunk)
            sha.update(chunk)
            f.write(chunk)

    return {
        "ok": True,
        "path": temp_path,
        "content_type": content_type,
        "size_bytes": size,
        "sha256": sha.hexdigest(),
        "suffix": suffix,
    }


def post_photo_metadata_to_fgo(payload: dict) -> dict:
    return fgo_post("/internal/proof/photo", payload)


def parse_fu_delivery_command(text: str) -> dict:
    raw = (text or "").strip()
    order_code = normalize_order_code(raw)

    if not order_code:
        return {}

    lower = raw.lower()
    is_fu = lower.startswith("fu ") and " ok" in lower
    is_ok = lower.startswith("ok ") or lower.startswith("完成")

    if not (is_fu or is_ok):
        return {}

    tail = raw.upper().split(order_code, 1)[-1]
    groups = re.findall(r"\b(\d{4,6})\b", tail)
    delivery_code = groups[-1] if groups else ""

    return {
        "order_code": order_code,
        "delivery_code": delivery_code,
    }


def post_delivery_code_to_fgo(payload: dict) -> dict:
    return fgo_post("/internal/delivery/code", payload)


def parse_line_binding_command(text: str) -> dict:
    raw = (text or "").strip()

    if not raw:
        return {}

    cleaned = re.sub(r"\s+", " ", raw).strip()
    lower = cleaned.lower()

    m = re.match(r"^(綁定|绑定)\s*(客戶|客户|顧客|顾客|用户|使用者)\s+(.+)$", cleaned)
    if m:
        return {"role": "CUSTOMER", "value": m.group(3).strip()}

    m = re.match(
        r"^(綁定|绑定)\s*(店家|商家|店鋪|店铺|store)\s+(.+)$",
        cleaned,
        flags=re.IGNORECASE,
    )
    if m:
        return {"role": "STORE", "value": m.group(3).strip().upper()}

    m = re.match(
        r"^(綁定|绑定)\s*(外送員|外送员|司機|司机|騎手|骑手|driver|shipper)\s+(.+)$",
        cleaned,
        flags=re.IGNORECASE,
    )
    if m:
        return {"role": "DRIVER", "value": m.group(3).strip().upper()}

    m = re.match(r"^bind\s+(customer|user|client)\s+(.+)$", lower)
    if m:
        return {"role": "CUSTOMER", "value": cleaned.split(" ", 2)[2].strip()}

    m = re.match(r"^bind\s+(store|shop)\s+(.+)$", lower)
    if m:
        return {"role": "STORE", "value": cleaned.split(" ", 2)[2].strip().upper()}

    m = re.match(r"^bind\s+(driver|shipper|rider)\s+(.+)$", lower)
    if m:
        return {"role": "DRIVER", "value": cleaned.split(" ", 2)[2].strip().upper()}

    return {}


def role_label(role: str) -> str:
    return {
        "CUSTOMER": "客戶",
        "STORE": "店家",
        "DRIVER": "外送員",
        "ADMIN": "管理員",
    }.get((role or "").upper(), role or "")


def handle_line_binding(user_id: str, reply_token: str, raw_text: str) -> bool:
    cmd = parse_line_binding_command(raw_text)

    if not cmd:
        return False

    role = cmd["role"]
    value = cmd["value"].strip()
    profile = get_line_profile(user_id)
    display_name = profile.get("displayName", "") or ""

    payload = {
        "line_user_id": user_id,
        "active_role": role,
        "line_display_name": display_name,
        "source": "LINE_BINDING_COMMAND",
        "created_at": now_iso(),
    }

    if role == "CUSTOMER":
        payload["customer_phone"] = re.sub(r"[^\d+]", "", value)
        payload["customer_name"] = display_name or "LINE Customer"

    elif role == "STORE":
        payload["store_code"] = value.upper()

    elif role == "DRIVER":
        payload["driver_code"] = value.upper()
        payload["driver_name"] = display_name or value.upper()

    result = fgo_bind_line_user(payload)
    body = result.get("body") or {}

    if result.get("ok") and body.get("ok"):
        active = bool(body.get("active"))
        pending = bool(body.get("pending"))
        urls = body.get("urls") or {}
        entry_url = urls.get("entry_url") or ""

        if active:
            reply_message(
                reply_token,
                [
                    text_message(
                        "✅ LINE 綁定完成\n"
                        f"角色：{role_label(role)}\n"
                        f"綁定資料：{value}\n"
                        f"LINE User ID：{user_id}\n\n"
                        f"我的入口：{entry_url}\n\n"
                        "之後輸入「我的入口」即可回到你的 FUGO 頁面。"
                    )
                ],
            )

        elif pending:
            pending_url = body.get("pending_url") or manual_bind_url(
                user_id,
                role.lower(),
            )

            reply_message(
                reply_token,
                [
                    text_message(
                        "⏳ 綁定申請已送出，等待管理員審核\n"
                        f"角色：{role_label(role)}\n"
                        f"申請資料：{value}\n"
                        f"LINE User ID：{user_id}\n\n"
                        "目前政策：\n"
                        "客戶：自動啟用\n"
                        "店家 / 外送員：需 Admin 審核後才能使用\n\n"
                        f"查看狀態：{pending_url}"
                    )
                ],
            )

            if FGO_ADMIN_LINE_USER_ID and FGO_ADMIN_LINE_USER_ID != user_id:
                push_text(
                    FGO_ADMIN_LINE_USER_ID,
                    "🔔 FUGO 新的 LINE 綁定審核\n"
                    f"角色：{role_label(role)}\n"
                    f"申請資料：{value}\n"
                    f"LINE User ID：{user_id}\n\n"
                    f"後台審核：{admin_approval_url()}",
                )

        else:
            reply_message(
                reply_token,
                [
                    text_message(
                        "綁定狀態未知 ⚠️\n"
                        f"Result: {json.dumps(body, ensure_ascii=False)[:1200]}"
                    )
                ],
            )

    else:
        manual_url = manual_bind_url(user_id, role.lower())

        reply_message(
            reply_token,
            [
                text_message(
                    "LINE 綁定失敗 ⚠️\n"
                    "請確認：\n"
                    "1. FGO_INTERNAL_SECRET 是否一致\n"
                    "2. FumapGo webapp 是否已部署\n"
                    "3. Store Code / Driver Code 格式是否正確\n\n"
                    f"你也可以手動綁定：{manual_url}\n\n"
                    f"Result: {json.dumps(result, ensure_ascii=False)[:1200]}"
                )
            ],
        )

    return True


def handle_my_entry(user_id: str, reply_token: str) -> bool:
    result = fgo_resolve_line_user(user_id)
    body = result.get("body") or {}

    if result.get("ok") and body.get("ok") and body.get("bound"):
        active = bool(body.get("active"))
        pending = bool(body.get("pending"))
        binding = body.get("binding") or {}
        active_role = body.get("active_role") or binding.get("active_role") or ""
        approval_status = binding.get("approval_status") or body.get("approval_status") or ""
        status = binding.get("status") or body.get("status") or ""

        if active:
            urls = body.get("urls") or {}
            entry_url = urls.get("entry_url") or ""

            reply_message(
                reply_token,
                [
                    text_message(
                        "✅ 我的 FUGO 入口\n"
                        f"角色：{role_label(active_role)}\n"
                        f"LINE User ID：{user_id}\n\n"
                        f"入口：{entry_url}\n\n"
                        f"信用區塊：{urls.get('block_url', '')}"
                    )
                ],
            )

            return True

        if pending:
            pending_url = body.get("pending_url") or manual_bind_url(
                user_id,
                active_role.lower(),
            )

            reply_message(
                reply_token,
                [
                    text_message(
                        "⏳ 你的帳號正在等待管理員審核\n"
                        f"角色：{role_label(active_role)}\n"
                        f"狀態：{status} / {approval_status}\n\n"
                        "店家與外送員需要 Admin 通過後才能進入正式頁面。\n\n"
                        f"查看狀態：{pending_url}"
                    )
                ],
            )

            return True

    bind_url = manual_bind_url(user_id, "customer")

    reply_message(
        reply_token,
        [
            text_message(
                "你尚未綁定 LINE 身份。\n\n"
                "請先輸入其中一種：\n"
                "綁定客戶 0900000000\n"
                "綁定店家 STO-DEMO-ROAST\n"
                "綁定外送員 DRV-DEMO\n\n"
                f"手動綁定：{bind_url}"
            )
        ],
    )

    return True


def handle_my_identity(user_id: str, reply_token: str) -> bool:
    result = fgo_resolve_line_user(user_id)
    body = result.get("body") or {}

    if result.get("ok") and body.get("ok") and body.get("bound"):
        binding = body.get("binding") or {}

        lines = [
            "我的 LINE 身份",
            f"LINE User ID：{user_id}",
            f"角色：{role_label(binding.get('active_role', ''))}",
            f"狀態：{binding.get('status', '')} / {binding.get('approval_status', '')}",
        ]

        if binding.get("customer_phone"):
            lines.append(f"客戶手機：{binding.get('customer_phone')}")

        if binding.get("store_code"):
            lines.append(
                f"店家：{binding.get('store_code')} / {binding.get('bound_store_name') or ''}"
            )

        if binding.get("driver_code"):
            lines.append(
                f"外送員：{binding.get('driver_code')} / {binding.get('bound_driver_name') or ''}"
            )

        if binding.get("approval_note"):
            lines.append(f"備註：{binding.get('approval_note')}")

        reply_message(reply_token, [text_message("\n".join(lines))])
        return True

    reply_message(
        reply_token,
        [
            text_message(
                "尚未綁定 LINE 身份。\n"
                "請輸入：綁定客戶 / 綁定店家 / 綁定外送員"
            )
        ],
    )

    return True


def handle_image_proof(user_id: str, message_id: str) -> dict:
    session = get_photo_session(user_id)
    order_code = session.get("order_code", "")
    actor_role = session.get("actor_role", "DRIVER")

    if not order_code:
        return {
            "ok": False,
            "need_session": True,
            "message": "請先輸入：photo FG-YYYYMMDD-XXXXXX\n再傳送交付照片。",
        }

    dl = download_line_content(message_id)

    if not dl.get("ok"):
        return {
            "ok": False,
            "message": "下載 LINE 照片失敗。",
            "download": dl,
        }

    file_name = f"{order_code}_{actor_role}_{message_id}{dl['suffix']}"
    drive = {
        "ok": False,
        "skipped": True,
        "error": "Drive upload not attempted",
    }

    try:
        drive = upload_to_google_drive(
            dl["path"],
            file_name,
            dl["content_type"],
        )
    except Exception as e:
        drive = {"ok": False, "error": str(e)}
        print(f"[GOOGLE_DRIVE_UPLOAD_ERROR] {e}", flush=True)

    payload = {
        "order_code": order_code,
        "actor_role": actor_role,
        "line_user_id": user_id,
        "line_message_id": message_id,
        "file_name": file_name,
        "content_type": dl["content_type"],
        "size_bytes": dl["size_bytes"],
        "image_sha256": dl["sha256"],
        "google_drive_file_id": drive.get("file_id", ""),
        "google_drive_url": drive.get("web_view_link", ""),
        "google_drive_download_url": drive.get("web_content_link", ""),
        "public_image_url": drive.get("public_image_url", ""),
        "drive_upload_result": drive,
        "created_at": now_iso(),
    }

    fgo = post_photo_metadata_to_fgo(payload)

    try:
        os.remove(dl["path"])
    except Exception:
        pass

    if fgo.get("ok"):
        clear_photo_session(user_id)

    return {
        "ok": bool(fgo.get("ok")),
        "order_code": order_code,
        "drive": drive,
        "fgo": fgo,
        "payload": payload,
    }


@app.get("/")
def index():
    return jsonify(
        {
            "ok": True,
            "app": "fumapgo-linehook",
            "mode": APP_MODE,
            "step": "6.9_LINEHOOK_COMPATIBILITY",
            "time": now_iso(),
        }
    )


@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "app": "fumapgo-linehook",
            "mode": APP_MODE,
            "step": "6.9_LINEHOOK_COMPATIBILITY",
            "line_channel_id_set": bool(LINE_CHANNEL_ID),
            "line_secret_set": bool(LINE_CHANNEL_SECRET),
            "line_access_token_set": bool(LINE_CHANNEL_ACCESS_TOKEN),
            "fgo_base_url": FGO_BASE_URL,
            "fgo_internal_secret_set": bool(FGO_INTERNAL_SECRET),
            "admin_line_user_id_set": bool(FGO_ADMIN_LINE_USER_ID),
            "google_drive_folder_set": bool(GOOGLE_DRIVE_PROOF_FOLDER_ID),
            "google_service_account_set": bool(
                GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_JSON_B64
            ),
            "internal_push_ready": bool(LINE_CHANNEL_ACCESS_TOKEN and FGO_INTERNAL_SECRET),
            "internal_push_image_ready": bool(LINE_CHANNEL_ACCESS_TOKEN and FGO_INTERNAL_SECRET),
            "photo_session_ready": bool(FGO_INTERNAL_SECRET),
            "routes": [
                "/callback",
                "/internal/push",
                "/internal/push-image",
                "/internal/photo-session",
            ],
            "time": now_iso(),
        }
    )


@app.post("/internal/push")
def internal_push():
    ok, error = require_internal_secret()

    if not ok:
        return json_fail(error, 401)

    payload = request.get_json(silent=True) or {}
    to = (payload.get("to") or payload.get("line_user_id") or "").strip()
    text = str(payload.get("text") or "").strip()

    if not to:
        return json_fail("to / line_user_id missing", 400)

    if not text:
        return json_fail("text missing", 400)

    result = push_text(to, text)

    return jsonify(
        {
            "ok": bool(result.get("ok")),
            "result": result,
            "time": now_iso(),
        }
    ), 200 if result.get("ok") else 502


@app.post("/internal/push-image")
def internal_push_image():
    ok, error = require_internal_secret()

    if not ok:
        return json_fail(error, 401)

    payload = request.get_json(silent=True) or {}
    to = (payload.get("to") or payload.get("line_user_id") or "").strip()
    image_url = (payload.get("image_url") or payload.get("originalContentUrl") or "").strip()
    preview_url = (payload.get("preview_url") or payload.get("previewImageUrl") or image_url).strip()
    text = str(payload.get("text") or "").strip()

    if not to:
        return json_fail("to / line_user_id missing", 400)

    if not image_url:
        return json_fail("image_url missing", 400)

    result = push_image(to, image_url, preview_url, text)

    return jsonify(
        {
            "ok": bool(result.get("ok")),
            "result": result,
            "time": now_iso(),
        }
    ), 200 if result.get("ok") else 502


@app.post("/internal/photo-session")
def internal_photo_session():
    ok, error = require_internal_secret()

    if not ok:
        return json_fail(error, 401)

    payload = request.get_json(silent=True) or {}
    line_user_id = (
        payload.get("line_user_id")
        or payload.get("to")
        or FGO_ADMIN_LINE_USER_ID
        or ""
    ).strip()

    order_code = normalize_order_code(payload.get("order_code") or "")
    actor_role = (payload.get("actor_role") or "DRIVER").upper()
    push_hint = bool(payload.get("push_hint", True))

    if not line_user_id:
        return json_fail("line_user_id missing", 400)

    if not order_code:
        return json_fail("order_code missing or invalid", 400)

    session = set_photo_session(line_user_id, order_code, actor_role)

    push_result = {"ok": True, "skipped": True}

    if push_hint:
        push_result = push_text(
            line_user_id,
            "📷 FumapGo 照片證明模式已啟用\n"
            f"訂單：{order_code}\n"
            f"角色：{role_label(actor_role)}\n\n"
            "請直接傳送照片。系統會把照片寫入訂單證明。\n"
            "建議：正式流程優先使用 webapp 上傳照片。",
        )

    return jsonify(
        {
            "ok": True,
            "session": session,
            "push_result": push_result,
            "time": now_iso(),
        }
    )


@app.post("/callback")
def callback():
    body = request.get_data()
    signature = request.headers.get("X-Line-Signature", "")

    if not verify_line_signature(body, signature):
        abort(400, "Invalid LINE signature")

    data = request.get_json(silent=True) or {}
    events = data.get("events", [])

    for event in events:
        event_type = event.get("type")
        reply_token = event.get("replyToken")
        source = event.get("source", {})
        user_id = source.get("userId", "")
        message = event.get("message", {})
        message_type = message.get("type")

        print(
            json.dumps(
                {
                    "event_type": event_type,
                    "message_type": message_type,
                    "user_id": user_id,
                    "time": now_iso(),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

        if event_type == "follow":
            reply_message(
                reply_token,
                [
                    text_message(
                        "歡迎加入 FUMAP GO 信用外送。\n"
                        "這裡是店家、外送員、顧客的 LINE 中心。\n\n"
                        + menu_text(user_id)
                    )
                ],
            )

        elif event_type == "message" and message_type == "text":
            raw_text = (message.get("text") or "").strip()
            lower = raw_text.lower()
            order_code = normalize_order_code(raw_text)

            if lower in {"help", "menu", "功能", "選單", "菜单", "開始", "start"}:
                reply_message(reply_token, [text_message(menu_text(user_id))])
                continue

            if lower == "ping":
                reply_message(
                    reply_token,
                    [
                        text_message(
                            "pong\n"
                            f"mode: {APP_MODE}\n"
                            f"time: {now_iso()}\n"
                            f"user_id: {user_id}"
                        )
                    ],
                )
                continue

            if handle_line_binding(user_id, reply_token, raw_text):
                continue

            if raw_text in {"我的入口", "入口", "my entry", "entry"}:
                handle_my_entry(user_id, reply_token)
                continue

            if raw_text in {"我的身份", "我的身分", "身份", "身分", "my identity"}:
                handle_my_identity(user_id, reply_token)
                continue

            if lower.startswith("photo ") and order_code:
                session = set_photo_session(user_id, order_code, "DRIVER")

                reply_message(
                    reply_token,
                    [
                        text_message(
                            "📷 照片證明模式已啟用\n"
                            f"訂單：{order_code}\n"
                            f"建立時間：{session['created_at']}\n\n"
                            "請直接傳送照片。系統會上傳並回寫 FumapGo。"
                        )
                    ],
                )
                continue

            fu_cmd = parse_fu_delivery_command(raw_text)

            if fu_cmd:
                payload = {
                    "order_code": fu_cmd["order_code"],
                    "delivery_code": fu_cmd.get("delivery_code", ""),
                    "line_user_id": user_id,
                    "source": "LINE_FU_COMMAND",
                    "created_at": now_iso(),
                }

                result = post_delivery_code_to_fgo(payload)

                if result.get("ok"):
                    reply_message(
                        reply_token,
                        [
                            text_message(
                                "✅ 收貨完成指令已送出\n"
                                f"訂單：{fu_cmd['order_code']}\n"
                                f"收貨碼：{fu_cmd.get('delivery_code') or '未提供'}"
                            )
                        ],
                    )
                else:
                    reply_message(
                        reply_token,
                        [
                            text_message(
                                "⚠️ 收貨完成指令送出失敗\n"
                                f"Result: {json.dumps(result, ensure_ascii=False)[:1200]}"
                            )
                        ],
                    )

                continue

            if order_code:
                reply_message(
                    reply_token,
                    [
                        text_message(
                            "FumapGo 訂單連結\n\n"
                            f"訂單：{order_code}\n"
                            f"客戶頁：{FGO_BASE_URL}/go/order/{order_code}\n"
                            f"外送頁：{FGO_BASE_URL}/driver/order/{order_code}?view=mobile&lang=zh\n"
                            f"證明頁：{FGO_BASE_URL}/proof/{order_code}?view=mobile&lang=zh\n\n"
                            "若要上傳照片備用：\n"
                            f"photo {order_code}"
                        )
                    ],
                )
                continue

            reply_message(
                reply_token,
                [
                    text_message(
                        "收到。\n\n"
                        "可輸入：\n"
                        "我的入口\n"
                        "我的身份\n"
                        "綁定客戶 0900000000\n"
                        "綁定店家 STO-XXXX\n"
                        "綁定外送員 DRV-XXXX\n"
                        "photo FG-訂單碼"
                    )
                ],
            )

        elif event_type == "message" and message_type == "image":
            message_id = message.get("id", "")

            result = handle_image_proof(user_id, message_id)

            if result.get("ok"):
                reply_message(
                    reply_token,
                    [
                        text_message(
                            "✅ 照片已收到並寫入 FumapGo\n"
                            f"訂單：{result.get('order_code')}\n\n"
                            "正式流程仍建議使用 Webapp 上傳，LINE 照片作為備用。"
                        )
                    ],
                )
            else:
                reply_message(
                    reply_token,
                    [
                        text_message(
                            result.get("message")
                            or "⚠️ 照片處理失敗，請稍後再試或聯絡管理員。"
                        )
                    ],
                )

        elif event_type == "postback":
            reply_message(
                reply_token,
                [
                    text_message(
                        "已收到操作。\n"
                        "目前主要操作請回到 FumapGo Webapp 完成。"
                    )
                ],
            )

    return jsonify({"ok": True, "time": now_iso()})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
