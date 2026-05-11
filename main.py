import os
import hmac
import base64
import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

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
APP_MODE = os.getenv("APP_MODE", "fumapgo")

GOOGLE_DRIVE_PROOF_FOLDER_ID = os.getenv("GOOGLE_DRIVE_PROOF_FOLDER_ID", "")
GOOGLE_SERVICE_ACCOUNT_JSON = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "")
GOOGLE_SERVICE_ACCOUNT_JSON_B64 = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_B64", "")

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_CONTENT_URL = "https://api-data.line.me/v2/bot/message/{message_id}/content"

SESSION_PATH = Path(os.getenv("PHOTO_SESSION_PATH", "/tmp/fumapgo_photo_sessions.json"))


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def line_headers(content_type="application/json"):
    headers = {"Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def verify_line_signature(body: bytes, signature: str) -> bool:
    if not LINE_CHANNEL_SECRET:
        return False
    digest = hmac.new(LINE_CHANNEL_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(expected, signature or "")


def text_message(text: str):
    return {"type": "text", "text": text[:5000]}


def reply_message(reply_token: str, messages: list):
    if not LINE_CHANNEL_ACCESS_TOKEN or not reply_token:
        return {"ok": False, "error": "missing token"}
    payload = {"replyToken": reply_token, "messages": messages[:5]}
    r = requests.post(LINE_REPLY_URL, headers=line_headers(), json=payload, timeout=15)
    return {"ok": r.ok, "status_code": r.status_code, "body": r.text[:500]}


def push_message(to: str, messages: list):
    if not LINE_CHANNEL_ACCESS_TOKEN or not to:
        return {"ok": False, "error": "missing token or target"}
    payload = {"to": to, "messages": messages[:5]}
    r = requests.post(LINE_PUSH_URL, headers=line_headers(), json=payload, timeout=15)
    return {"ok": r.ok, "status_code": r.status_code, "body": r.text[:500]}


def menu_text(user_id: str = ""):
    return (
        "FUMAP GO 信用外送\n"
        "請選擇功能：\n\n"
        f"店家入口：{FGO_BASE_URL}/store?view=mobile&lang=zh\n"
        f"外送員接單：{FGO_BASE_URL}/driver?view=mobile&lang=zh\n"
        f"顧客收貨：{FGO_BASE_URL}/customer?view=mobile&lang=zh\n"
        f"信用區塊：{FGO_BASE_URL}/block?view=mobile&lang=zh\n"
        f"爭議中心：{FGO_BASE_URL}/dispute?view=mobile&lang=zh\n"
        f"我的錢包：{FGO_BASE_URL}/wallet?view=mobile&lang=zh\n\n"
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
        SESSION_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
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
        # Step 11A robustness:
        # If the value is raw JSON by mistake, accept it.
        # Otherwise decode it as base64.
        if candidate.startswith("{"):
            raw = candidate
        else:
            raw = base64.b64decode(candidate).decode("utf-8")

    if not raw:
        raise RuntimeError("GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_JSON_B64 is not set")

    info = json.loads(raw)
    scopes = ["https://www.googleapis.com/auth/drive.file"]
    return service_account.Credentials.from_service_account_info(info, scopes=scopes)


def upload_to_google_drive(local_path: str, file_name: str, mime_type: str) -> dict:
    if not GOOGLE_DRIVE_PROOF_FOLDER_ID:
        return {"ok": False, "skipped": True, "error": "GOOGLE_DRIVE_PROOF_FOLDER_ID not set"}

    creds = get_google_credentials()
    service = build("drive", "v3", credentials=creds)

    metadata = {
        "name": file_name,
        "parents": [GOOGLE_DRIVE_PROOF_FOLDER_ID],
    }
    media = MediaFileUpload(local_path, mimetype=mime_type or "image/jpeg", resumable=False)
    created = service.files().create(
        body=metadata,
        media_body=media,
        fields="id,name,webViewLink,webContentLink",
    ).execute()

    # Try to make the proof viewable by link. If this fails, keep file id anyway.
    try:
        service.permissions().create(
            fileId=created["id"],
            body={"type": "anyone", "role": "reader"},
            fields="id",
        ).execute()
    except Exception as e:
        print(f"[GOOGLE_DRIVE_PERMISSION_WARNING] {e}", flush=True)

    return {
        "ok": True,
        "file_id": created.get("id", ""),
        "name": created.get("name", file_name),
        "web_view_link": created.get("webViewLink", ""),
        "web_content_link": created.get("webContentLink", ""),
    }


def download_line_content(message_id: str) -> dict:
    url = LINE_CONTENT_URL.format(message_id=message_id)
    r = requests.get(url, headers=line_headers(content_type=None), stream=True, timeout=30)
    if not r.ok:
        return {"ok": False, "status_code": r.status_code, "error": r.text[:500]}

    content_type = r.headers.get("Content-Type", "image/jpeg")
    suffix = ".jpg"
    if "png" in content_type:
        suffix = ".png"
    elif "webp" in content_type:
        suffix = ".webp"
    elif "gif" in content_type:
        suffix = ".gif"

    fd, temp_path = tempfile.mkstemp(prefix="fgo_line_photo_", suffix=suffix)
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
    if not FGO_INTERNAL_SECRET:
        return {"ok": False, "error": "FGO_INTERNAL_SECRET not set"}

    url = f"{FGO_BASE_URL}/internal/proof/photo"
    headers = {
        "Content-Type": "application/json",
        "X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET,
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return {"ok": r.ok, "status_code": r.status_code, "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}



def parse_fu_delivery_command(text: str) -> dict:
    """
    Supported:
      fu FG-20260511-074026 ok 8893
      ok FG-20260511-074026 8893
      完成 FG-20260511-074026 8893
    """
    raw = (text or "").strip()
    order_code = normalize_order_code(raw)
    if not order_code:
        return {}

    lower = raw.lower()
    is_fu = lower.startswith("fu ") and " ok" in lower
    is_ok = lower.startswith("ok ") or lower.startswith("完成")
    if not (is_fu or is_ok):
        return {}

    # Extract digits after the order code. Use last 4-6 digit group as delivery code.
    tail = raw.upper().split(order_code, 1)[-1]
    groups = re.findall(r"\b(\d{4,6})\b", tail)
    delivery_code = groups[-1] if groups else ""

    return {
        "order_code": order_code,
        "delivery_code": delivery_code,
    }


def post_delivery_code_to_fgo(payload: dict) -> dict:
    if not FGO_INTERNAL_SECRET:
        return {"ok": False, "error": "FGO_INTERNAL_SECRET not set"}

    url = f"{FGO_BASE_URL}/internal/delivery/code"
    headers = {
        "Content-Type": "application/json",
        "X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET,
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text[:500]}
        return {"ok": r.ok, "status_code": r.status_code, "body": body}
    except Exception as e:
        return {"ok": False, "error": str(e)}



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
        return {"ok": False, "message": "下載 LINE 照片失敗。", "download": dl}

    file_name = f"{order_code}_{actor_role}_{message_id}{dl['suffix']}"
    drive = {"ok": False, "skipped": True, "error": "Drive upload not attempted"}

    try:
        drive = upload_to_google_drive(dl["path"], file_name, dl["content_type"])
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
    return jsonify({
        "ok": True,
        "app": "fumapgo-linehook",
        "mode": APP_MODE,
        "time": now_iso(),
    })


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "app": "fumapgo-linehook",
        "mode": APP_MODE,
        "line_channel_id_set": bool(LINE_CHANNEL_ID),
        "line_secret_set": bool(LINE_CHANNEL_SECRET),
        "line_access_token_set": bool(LINE_CHANNEL_ACCESS_TOKEN),
        "fgo_base_url": FGO_BASE_URL,
        "fgo_internal_secret_set": bool(FGO_INTERNAL_SECRET),
        "admin_line_user_id_set": bool(FGO_ADMIN_LINE_USER_ID),
        "google_drive_folder_set": bool(GOOGLE_DRIVE_PROOF_FOLDER_ID),
        "google_service_account_set": bool(GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_JSON_B64),
        "time": now_iso(),
    })


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

        print(json.dumps({
            "event_type": event_type,
            "message_type": message_type,
            "user_id": user_id,
            "time": now_iso(),
        }, ensure_ascii=False), flush=True)

        if event_type == "follow":
            reply_message(reply_token, [text_message(
                "歡迎加入 FUMAP GO 信用外送。\n"
                "這裡是店家、外送員、顧客的連結中心。\n\n"
                + menu_text(user_id)
            )])

        elif event_type == "message" and message_type == "text":
            raw_text = (message.get("text") or "").strip()
            text = raw_text.lower()
            order_code = normalize_order_code(raw_text)

            if text in ["ping", "test", "測試"]:
                reply_message(reply_token, [text_message(
                    "pong ✅\n"
                    "FUMAP GO LINE webhook 已連線。\n"
                    f"User ID：{user_id}"
                )])

            elif text in ["menu", "選單", "功能", "開始", "start"]:
                reply_message(reply_token, [text_message(menu_text(user_id))])

            elif text in ["clear photo", "取消拍照", "清除拍照"]:
                clear_photo_session(user_id)
                reply_message(reply_token, [text_message("已清除拍照綁定。")])

            elif parse_fu_delivery_command(raw_text):
                cmd = parse_fu_delivery_command(raw_text)
                if not cmd.get("delivery_code"):
                    reply_message(reply_token, [text_message(
                        "請補上收貨碼後四碼，例如：\n"
                        f"fu {cmd['order_code']} ok 8893\n\n"
                        "面交完成需要收貨碼，避免爭議。"
                    )])
                else:
                    result = post_delivery_code_to_fgo({
                        "order_code": cmd["order_code"],
                        "delivery_code": cmd["delivery_code"],
                        "line_user_id": user_id,
                        "actor_role": "DRIVER",
                        "source": "LINE_FU_OK_COMMAND",
                        "created_at": now_iso(),
                    })
                    if result.get("ok"):
                        proof_url = f"{FGO_BASE_URL}/proof/{cmd['order_code']}?role=customer&view=mobile&lang=zh"
                        reply_message(reply_token, [text_message(
                            "✅ 面交收貨碼已確認\n"
                            f"訂單：{cmd['order_code']}\n"
                            "DELIVERY_CODE_BLOCK 已建立。\n\n"
                            f"證明頁：{proof_url}"
                        )])
                        if FGO_ADMIN_LINE_USER_ID and FGO_ADMIN_LINE_USER_ID != user_id:
                            push_message(FGO_ADMIN_LINE_USER_ID, [text_message(
                                "✅ FUGO 訂單已用收貨碼完成\n"
                                f"訂單：{cmd['order_code']}\n"
                                f"證明頁：{proof_url}"
                            )])
                    else:
                        reply_message(reply_token, [text_message(
                            "收貨碼確認失敗 ⚠️\n"
                            "請確認訂單碼、後四碼、FGO internal secret。\n\n"
                            f"Result: {json.dumps(result, ensure_ascii=False)[:900]}"
                        )])

            elif text.startswith("photo") or text.startswith("拍照"):
                if not order_code:
                    reply_message(reply_token, [text_message(
                        "請輸入訂單碼，例如：\n"
                        "photo FG-20260510-9570E4\n\n"
                        "然後再傳送交付照片。"
                    )])
                else:
                    set_photo_session(user_id, order_code, actor_role="DRIVER")
                    reply_message(reply_token, [text_message(
                        f"已綁定照片證明訂單：{order_code}\n"
                        "現在請直接傳送交付照片。\n\n"
                        "系統會下載 LINE 照片、上傳 Google Drive，並回寫 FGO 建立 PHOTO_DELIVERY_BLOCK。\n\n"
                        f"若為面交收貨碼完成，也可以輸入：fu {order_code} ok 後四碼"
                    )])

            elif text.startswith("bind"):
                reply_message(reply_token, [text_message(
                    "綁定功能準備中。\n"
                    "下一步支援：bind driver / bind store / bind customer。\n"
                    f"你的 LINE User ID：{user_id}"
                )])

            else:
                reply_message(reply_token, [text_message(
                    "已收到訊息。\n"
                    "請輸入「menu」查看功能。\n"
                    "若要上傳交付照片，請輸入：photo FG-訂單碼。"
                )])

        elif event_type == "message" and message_type == "image":
            message_id = message.get("id", "")
            result = handle_image_proof(user_id, message_id)

            if result.get("need_session"):
                reply_message(reply_token, [text_message(result["message"])])
            elif result.get("ok"):
                drive_url = result["payload"].get("google_drive_url") or "未設定 Google Drive / 尚無連結"
                proof_url = f"{FGO_BASE_URL}/proof/{result['order_code']}?view=mobile&lang=zh"
                reply_message(reply_token, [text_message(
                    "已收到照片 ✅\n"
                    f"訂單：{result['order_code']}\n"
                    "PHOTO_DELIVERY_BLOCK 已建立。\n\n"
                    f"證明頁：{proof_url}\n"
                    f"Google Drive：{drive_url}"
                )])

                if FGO_ADMIN_LINE_USER_ID and FGO_ADMIN_LINE_USER_ID != user_id:
                    push_message(FGO_ADMIN_LINE_USER_ID, [text_message(
                        "📷 FUMAP GO 交付照片已上傳\n"
                        f"訂單：{result['order_code']}\n"
                        f"證明頁：{proof_url}\n"
                        f"Google Drive：{drive_url}"
                    )])
            else:
                reply_message(reply_token, [text_message(
                    "照片處理失敗 ⚠️\n"
                    "請確認 Google Drive / FGO internal proof endpoint / internal secret。\n\n"
                    f"LINE messageId：{message_id}"
                )])
                print(json.dumps({"photo_proof_error": result}, ensure_ascii=False), flush=True)

        elif event_type == "postback":
            reply_message(reply_token, [text_message("已收到操作。")])

    return "OK", 200


@app.post("/internal/push")
def internal_push():
    secret = request.headers.get("X-FGO-INTERNAL-SECRET", "")
    if FGO_INTERNAL_SECRET and secret != FGO_INTERNAL_SECRET:
        abort(403, "Forbidden")

    payload = request.get_json(silent=True) or {}
    to = (
        payload.get("to")
        or payload.get("line_user_id")
        or payload.get("admin_line_user_id")
        or FGO_ADMIN_LINE_USER_ID
    )
    text = payload.get("text") or "FUMAP GO notification"

    if not to:
        return jsonify({
            "ok": False,
            "error": "missing target LINE user id",
            "hint": "Set FGO_ADMIN_LINE_USER_ID on linehook or send payload.to",
        }), 400

    result = push_message(to, [text_message(text)])
    return jsonify(result)


@app.post("/internal/photo-session")
def internal_photo_session():
    secret = request.headers.get("X-FGO-INTERNAL-SECRET", "")
    if FGO_INTERNAL_SECRET and secret != FGO_INTERNAL_SECRET:
        abort(403, "Forbidden")

    payload = request.get_json(silent=True) or {}
    order_code = normalize_order_code(payload.get("order_code", ""))
    line_user_id = payload.get("line_user_id") or payload.get("to") or FGO_ADMIN_LINE_USER_ID
    actor_role = payload.get("actor_role") or "DRIVER"

    if not order_code:
        return jsonify({"ok": False, "error": "missing valid order_code"}), 400
    if not line_user_id:
        return jsonify({"ok": False, "error": "missing line_user_id and FGO_ADMIN_LINE_USER_ID"}), 400

    session = set_photo_session(line_user_id, order_code, actor_role)
    push_result = None
    if payload.get("push_hint", True):
        push_result = push_message(line_user_id, [text_message(
            f"📷 FUGO 交付證明\n"
            f"訂單：{order_code}\n\n"
            "拍照交付：請直接在此聊天室傳送照片，系統會自動建立 PHOTO_DELIVERY_BLOCK。\n\n"
            f"手交收貨碼：輸入 fu {order_code} ok 後四碼\n"
            f"例如：fu {order_code} ok 8893"
        )])

    return jsonify({
        "ok": True,
        "line_user_id": line_user_id,
        "session": session,
        "push_result": push_result,
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
