import os
import hmac
import base64
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import quote_plus

import requests
from flask import Flask, request, jsonify, abort


app = Flask(__name__)


LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_CHANNEL_ID = os.getenv("LINE_CHANNEL_ID", "")

FGO_BASE_URL = os.getenv("FGO_BASE_URL", "https://fumapgo.onrender.com").rstrip("/")
FGO_INTERNAL_SECRET = os.getenv("FGO_INTERNAL_SECRET", "")
FGO_ADMIN_LINE_USER_ID = os.getenv("FGO_ADMIN_LINE_USER_ID", "")
APP_MODE = os.getenv("APP_MODE", "fumapgo-linehook-step6-15-notification-gateway")

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_PROFILE_URL = "https://api.line.me/v2/bot/profile/{user_id}"


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def json_ok(**kwargs):
    return jsonify({"ok": True, **kwargs})


def json_fail(message, status_code=400, **kwargs):
    return jsonify({"ok": False, "error": message, **kwargs}), status_code


def line_headers(content_type="application/json"):
    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
    }

    if content_type:
        headers["Content-Type"] = content_type

    return headers


def fgo_headers():
    return {
        "Content-Type": "application/json",
        "X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET,
    }


def verify_line_signature(body, signature):
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


def text_message(text):
    return {
        "type": "text",
        "text": str(text or "")[:5000],
    }


def image_message(image_url, preview_url=""):
    preview_url = preview_url or image_url

    return {
        "type": "image",
        "originalContentUrl": image_url,
        "previewImageUrl": preview_url,
    }


def reply_message(reply_token, messages):
    if not LINE_CHANNEL_ACCESS_TOKEN:
        return {"ok": False, "error": "LINE_CHANNEL_ACCESS_TOKEN not set"}

    if not reply_token:
        return {"ok": False, "error": "reply_token missing"}

    payload = {
        "replyToken": reply_token,
        "messages": messages[:5],
    }

    try:
        r = requests.post(
            LINE_REPLY_URL,
            headers=line_headers(),
            json=payload,
            timeout=10,
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


def push_message(to, messages):
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
            timeout=10,
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


def push_text(to, text):
    return push_message(to, [text_message(text)])


def push_image(to, image_url, preview_url="", text=""):
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


def get_line_profile(user_id):
    if not LINE_CHANNEL_ACCESS_TOKEN or not user_id:
        return {}

    try:
        url = LINE_PROFILE_URL.format(user_id=quote_plus(user_id))
        r = requests.get(
            url,
            headers=line_headers(content_type=None),
            timeout=8,
        )

        if not r.ok:
            return {}

        return r.json()

    except Exception:
        return {}


def fgo_get(path, params=None):
    if not FGO_INTERNAL_SECRET:
        return {"ok": False, "error": "FGO_INTERNAL_SECRET not set"}

    try:
        r = requests.get(
            f"{FGO_BASE_URL}{path}",
            headers={
                "X-FGO-INTERNAL-SECRET": FGO_INTERNAL_SECRET,
            },
            params=params or {},
            timeout=10,
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


def resolve_line_user(line_user_id):
    return fgo_get(
        "/internal/line/resolve",
        {
            "line_user_id": line_user_id,
        },
    )


def role_label(role):
    role = (role or "").upper()

    return {
        "CUSTOMER": "客戶",
        "STORE": "店家",
        "DRIVER": "外送員",
        "ADMIN": "管理員",
    }.get(role, role or "未知")


def web_register_url(role, line_user_id=""):
    role = (role or "customer").lower()
    line_user_id = quote_plus(line_user_id or "")

    if role == "store":
        return f"{FGO_BASE_URL}/store/register?line_user_id={line_user_id}&view=mobile&lang=zh"

    if role in ("driver", "shipper"):
        return f"{FGO_BASE_URL}/driver/register?line_user_id={line_user_id}&view=mobile&lang=zh"

    return f"{FGO_BASE_URL}/customer/register?line_user_id={line_user_id}&view=mobile&lang=zh"


def web_line_bind_url(role, line_user_id=""):
    role = quote_plus((role or "customer").lower())
    line_user_id = quote_plus(line_user_id or "")

    return f"{FGO_BASE_URL}/line/register?role={role}&line_user_id={line_user_id}&view=mobile&lang=zh"


def admin_ops_url():
    return f"{FGO_BASE_URL}/admin/ops?view=desktop&lang=zh"


def menu_text(user_id=""):
    customer_register = web_register_url("customer", user_id)
    store_register = web_register_url("store", user_id)
    driver_register = web_register_url("driver", user_id)

    customer_bind = web_line_bind_url("customer", user_id)
    store_bind = web_line_bind_url("store", user_id)
    driver_bind = web_line_bind_url("driver", user_id)

    return (
        "FumapGo LINE 通知中心\n\n"
        "現在的規則：\n"
        "Webapp = 註冊 / 下單 / 上傳照片 / 營運\n"
        "LINE = 推送通知 / 客服 / 回到 webapp\n\n"
        "【快速註冊】\n"
        f"客戶註冊：{customer_register}\n"
        f"店家註冊：{store_register}\n"
        f"外送員註冊：{driver_register}\n\n"
        "【LINE 綁定】\n"
        f"客戶 LINE 綁定：{customer_bind}\n"
        f"店家 LINE 綁定：{store_bind}\n"
        f"外送員 LINE 綁定：{driver_bind}\n\n"
        "【主要入口】\n"
        f"Marketplace：{FGO_BASE_URL}/go?view=mobile&lang=zh\n"
        f"店家工作台：{FGO_BASE_URL}/store?view=mobile&lang=zh\n"
        f"外送員工作台：{FGO_BASE_URL}/driver?view=mobile&lang=zh\n"
        f"客服：{FGO_BASE_URL}/support/new?view=mobile&lang=zh\n\n"
        "可輸入：\n"
        "我的入口\n"
        "我的身份\n"
        "客服 + 你的問題\n\n"
        f"你的 LINE User ID：{user_id}"
    )


def build_entry_text(user_id):
    result = resolve_line_user(user_id)
    body = result.get("body") or {}

    if result.get("ok") and body.get("ok") and body.get("bound"):
        binding = body.get("binding") or {}
        urls = body.get("urls") or {}

        active = bool(body.get("active"))
        pending = bool(body.get("pending"))

        role = body.get("active_role") or binding.get("active_role") or ""
        status = binding.get("status") or body.get("status") or ""
        approval = binding.get("approval_status") or body.get("approval_status") or ""

        if active:
            return (
                "✅ 我的 FumapGo 入口\n\n"
                f"角色：{role_label(role)}\n"
                f"狀態：{status} / {approval}\n"
                f"LINE User ID：{user_id}\n\n"
                f"入口：{urls.get('entry_url', '')}\n"
                f"通知中心：{urls.get('notification_url', '')}\n"
                f"信用區塊：{urls.get('block_url', '')}\n\n"
                "LINE 只負責通知與客服，所有操作請回 webapp。"
            )

        if pending:
            return (
                "⏳ 你的帳號正在等待管理員審核\n\n"
                f"角色：{role_label(role)}\n"
                f"狀態：{status} / {approval}\n"
                f"LINE User ID：{user_id}\n\n"
                f"查看狀態：{body.get('pending_url') or web_line_bind_url(role, user_id)}"
            )

    return (
        "你目前還沒有完成 LINE 綁定。\n\n"
        "請使用下方其中一個入口完成 webapp 註冊或 LINE 綁定：\n\n"
        f"客戶註冊：{web_register_url('customer', user_id)}\n"
        f"店家註冊：{web_register_url('store', user_id)}\n"
        f"外送員註冊：{web_register_url('driver', user_id)}\n\n"
        f"客戶 LINE 綁定：{web_line_bind_url('customer', user_id)}\n\n"
        f"你的 LINE User ID：{user_id}"
    )


def build_identity_text(user_id):
    result = resolve_line_user(user_id)
    body = result.get("body") or {}

    if result.get("ok") and body.get("ok") and body.get("bound"):
        binding = body.get("binding") or {}
        role = binding.get("active_role") or body.get("active_role") or ""
        status = binding.get("status") or body.get("status") or ""
        approval = binding.get("approval_status") or body.get("approval_status") or ""

        lines = [
            "我的 LINE 身份",
            f"LINE User ID：{user_id}",
            f"角色：{role_label(role)}",
            f"狀態：{status} / {approval}",
        ]

        if binding.get("customer_phone"):
            lines.append(f"客戶手機：{binding.get('customer_phone')}")

        if binding.get("store_code"):
            lines.append(f"店家：{binding.get('store_code')} / {binding.get('bound_store_name') or ''}")

        if binding.get("driver_code"):
            lines.append(f"外送員：{binding.get('driver_code')} / {binding.get('bound_driver_name') or ''}")

        if binding.get("approval_note"):
            lines.append(f"備註：{binding.get('approval_note')}")

        return "\n".join(lines)

    return (
        "尚未綁定 LINE 身份。\n\n"
        f"客戶綁定：{web_line_bind_url('customer', user_id)}\n"
        f"店家綁定：{web_line_bind_url('store', user_id)}\n"
        f"外送員綁定：{web_line_bind_url('driver', user_id)}\n\n"
        f"LINE User ID：{user_id}"
    )


def forward_customer_service_to_admin(user_id, text="", event_type="text"):
    if not FGO_ADMIN_LINE_USER_ID:
        return {"ok": False, "skipped": True, "error": "FGO_ADMIN_LINE_USER_ID not set"}

    profile = get_line_profile(user_id)
    name = profile.get("displayName", "")

    admin_text = (
        "📩 FumapGo LINE CSKH\n\n"
        f"User：{name or '-'}\n"
        f"LINE User ID：{user_id}\n"
        f"Type：{event_type}\n"
        f"Time：{now_iso()}\n\n"
        f"Message：\n{text or '-'}\n\n"
        "Ghi chú: LINE hiện chỉ là CSKH + push. Nghiệp vụ chính xử lý trong webapp."
    )

    return push_text(FGO_ADMIN_LINE_USER_ID, admin_text)


def handle_text_message(user_id, reply_token, text):
    raw = (text or "").strip()
    lower = raw.lower()

    menu_keywords = {
        "menu",
        "help",
        "hi",
        "hello",
        "start",
        "開始",
        "菜单",
        "選單",
        "功能",
        "幫助",
        "帮助",
    }

    if lower in menu_keywords or raw in menu_keywords:
        return reply_message(reply_token, [text_message(menu_text(user_id))])

    if raw in ("我的入口", "入口", "my entry", "My entry"):
        return reply_message(reply_token, [text_message(build_entry_text(user_id))])

    if raw in ("我的身份", "身份", "我的id", "我的ID", "my id", "My ID"):
        return reply_message(reply_token, [text_message(build_identity_text(user_id))])

    if raw.startswith("客服") or lower.startswith("cskh") or lower.startswith("support"):
        forward_customer_service_to_admin(user_id, raw, event_type="support_text")

        return reply_message(
            reply_token,
            [
                text_message(
                    "已收到你的客服訊息。\n\n"
                    "Admin 會透過 LINE 或 webapp CSKH 回覆。\n"
                    "若是訂單問題，請附上訂單碼。"
                )
            ],
        )

    # Old command cleanup:
    # We no longer process binding/proof/business commands in LINE.
    legacy_prefixes = (
        "綁定",
        "绑定",
        "bind ",
        "photo ",
        "fu ",
        "ok ",
        "完成",
    )

    if lower.startswith(legacy_prefixes) or raw.startswith(("綁定", "绑定", "完成")):
        return reply_message(
            reply_token,
            [
                text_message(
                    "此 LINE 指令已停用。\n\n"
                    "現在 FumapGo 的正式流程如下：\n"
                    "1. 註冊、下單、上傳照片都在 webapp\n"
                    "2. LINE 只負責推送通知與客服\n\n"
                    f"請使用 webapp：{FGO_BASE_URL}/go?view=mobile&lang=zh\n\n"
                    f"客戶註冊：{web_register_url('customer', user_id)}\n"
                    f"店家註冊：{web_register_url('store', user_id)}\n"
                    f"外送員註冊：{web_register_url('driver', user_id)}"
                )
            ],
        )

    forward_customer_service_to_admin(user_id, raw, event_type="free_text")

    return reply_message(
        reply_token,
        [
            text_message(
                "已收到訊息。\n\n"
                "LINE 目前作為通知與客服中心使用。\n"
                "如需操作訂單、上傳付款或送達照片，請回到 webapp。\n\n"
                f"Marketplace：{FGO_BASE_URL}/go?view=mobile&lang=zh\n"
                "輸入「menu」可查看入口。"
            )
        ],
    )


@app.get("/")
def index():
    return json_ok(
        module="FumapGo LINE Notification Gateway",
        mode=APP_MODE,
        health="/health",
    )


@app.get("/health")
def health():
    return json_ok(
        module="FumapGo LINE Notification Gateway Step 6.15",
        mode=APP_MODE,
        fgo_base_url=FGO_BASE_URL,
        line_token_set=bool(LINE_CHANNEL_ACCESS_TOKEN),
        line_secret_set=bool(LINE_CHANNEL_SECRET),
        internal_secret_set=bool(FGO_INTERNAL_SECRET),
        admin_line_set=bool(FGO_ADMIN_LINE_USER_ID),
        routes=[
            "/callback",
            "/internal/push",
            "/internal/push-image",
            "/internal/photo-session",
        ],
    )


@app.post("/internal/push")
def internal_push():
    ok, error = require_internal_secret()

    if not ok:
        return json_fail(error, 401)

    payload = request.get_json(silent=True) or {}

    to = (
        payload.get("to")
        or payload.get("line_user_id")
        or payload.get("target_line_user_id")
        or ""
    ).strip()

    if to.upper() == "ADMIN":
        to = FGO_ADMIN_LINE_USER_ID

    text = str(payload.get("text") or payload.get("message") or "").strip()

    if not to:
        return json_fail("to / line_user_id missing", 400)

    if not text:
        return json_fail("text missing", 400)

    result = push_text(to, text)

    if not result.get("ok"):
        return jsonify(
            {
                "ok": False,
                "line_result": result,
            }
        ), 502

    return json_ok(
        line_result=result,
    )


@app.post("/internal/push-image")
def internal_push_image():
    ok, error = require_internal_secret()

    if not ok:
        return json_fail(error, 401)

    payload = request.get_json(silent=True) or {}

    to = (
        payload.get("to")
        or payload.get("line_user_id")
        or payload.get("target_line_user_id")
        or ""
    ).strip()

    if to.upper() == "ADMIN":
        to = FGO_ADMIN_LINE_USER_ID

    image_url = str(payload.get("image_url") or payload.get("public_image_url") or "").strip()
    preview_url = str(payload.get("preview_url") or payload.get("preview_image_url") or image_url).strip()
    text = str(payload.get("text") or payload.get("message") or "").strip()

    if not to:
        return json_fail("to / line_user_id missing", 400)

    if not image_url:
        return json_fail("image_url missing", 400)

    result = push_image(to, image_url, preview_url, text)

    if not result.get("ok"):
        return jsonify(
            {
                "ok": False,
                "line_result": result,
            }
        ), 502

    return json_ok(
        line_result=result,
    )


@app.post("/internal/photo-session")
def internal_photo_session():
    """Compatibility endpoint.

    Old webapp code may still call /internal/photo-session.
    This gateway no longer stores photo sessions or uploads LINE images.
    It only sends a hint link back to the target LINE user.
    """
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

    order_code = str(payload.get("order_code") or "").strip()
    actor_role = str(payload.get("actor_role") or "DRIVER").strip().upper()

    if not line_user_id:
        return json_fail("line_user_id missing", 400)

    if not order_code:
        return json_fail("order_code missing", 400)

    if actor_role == "DRIVER":
        link = f"{FGO_BASE_URL}/driver/order/{quote_plus(order_code)}?view=mobile&lang=zh"
    else:
        link = f"{FGO_BASE_URL}/go/order/{quote_plus(order_code)}?view=mobile&lang=zh"

    text = (
        "📷 FumapGo 送達照片請回 webapp 上傳\n\n"
        f"訂單：{order_code}\n"
        f"角色：{actor_role}\n\n"
        "LINE 不再接收照片作為正式 proof。\n"
        "請開啟 webapp 上傳，系統會記錄 block 並推送通知。\n\n"
        f"{link}"
    )

    result = push_text(line_user_id, text)

    return json_ok(
        compatibility=True,
        message="photo-session is deprecated; pushed webapp upload link instead",
        line_result=result,
    )


@app.post("/callback")
def callback():
    body = request.get_data()
    signature = request.headers.get("X-Line-Signature", "")

    if not verify_line_signature(body, signature):
        abort(403)

    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    events = payload.get("events") or []

    for event in events:
        try:
            event_type = event.get("type", "")
            source = event.get("source") or {}
            user_id = source.get("userId", "")
            reply_token = event.get("replyToken", "")

            if event_type == "follow":
                if user_id and reply_token:
                    reply_message(reply_token, [text_message(menu_text(user_id))])

                if user_id:
                    forward_customer_service_to_admin(
                        user_id,
                        "User followed FumapGo LINE bot.",
                        event_type="follow",
                    )

                continue

            if event_type == "message":
                message = event.get("message") or {}
                message_type = message.get("type", "")

                if message_type == "text":
                    text = message.get("text", "")
                    handle_text_message(user_id, reply_token, text)
                    continue

                if message_type == "image":
                    forward_customer_service_to_admin(
                        user_id,
                        "User sent an image in LINE. Image is not stored by linehook. Ask user to upload proof in webapp if needed.",
                        event_type="image",
                    )

                    reply_message(
                        reply_token,
                        [
                            text_message(
                                "已收到圖片提醒，但 LINE 不再作為正式上傳 proof 的地方。\n\n"
                                "付款截圖 / 送達照片請到 webapp 上傳，系統才會記錄 block。\n\n"
                                f"Marketplace：{FGO_BASE_URL}/go?view=mobile&lang=zh\n"
                                f"客服：{FGO_BASE_URL}/support/new?view=mobile&lang=zh"
                            )
                        ],
                    )

                    continue

                forward_customer_service_to_admin(
                    user_id,
                    f"Unsupported LINE message type: {message_type}",
                    event_type=message_type,
                )

                if reply_token:
                    reply_message(
                        reply_token,
                        [
                            text_message(
                                "此類訊息已收到，但正式操作請回 webapp。\n"
                                "輸入 menu 可查看入口。"
                            )
                        ],
                    )

                continue

            if event_type in ("postback", "join", "memberJoined"):
                if reply_token:
                    reply_message(reply_token, [text_message(menu_text(user_id))])

                continue

        except Exception as e:
            print(f"[CALLBACK_EVENT_ERROR] {e}", flush=True)

            try:
                if FGO_ADMIN_LINE_USER_ID:
                    push_text(
                        FGO_ADMIN_LINE_USER_ID,
                        "⚠️ FumapGo linehook callback error\n\n"
                        f"Error: {e}\n"
                        f"Time: {now_iso()}",
                    )
            except Exception:
                pass

    return "OK"


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
