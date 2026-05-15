import os
import hmac
import base64
import hashlib
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
APP_MODE = os.getenv("APP_MODE", "fumapgo-linehook-commercial-binding-gateway")

# P0 security:
# LINE must never expose admin URL/token. Admin support falls back to email.
ADMIN_CONTACT_EMAIL = os.getenv("ADMIN_CONTACT_EMAIL", "panjiaphu@gmail.com")
PUBLIC_MARKETPLACE_URL = os.getenv(
    "PUBLIC_MARKETPLACE_URL",
    f"{FGO_BASE_URL}/go?view=mobile&lang=zh",
)

# Kept only for backward ENV compatibility. Do not use for CSKH forwarding.
FGO_ADMIN_LINE_USER_ID = os.getenv("FGO_ADMIN_LINE_USER_ID", "")

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_PROFILE_URL = "https://api.line.me/v2/bot/profile/{user_id}"


DANGEROUS_LINE_TEXT_KEYS = (
    "/admin",
    "admin/ops",
    "admin/accounting",
    "admin/line-bindings",
    "admin/commercial",
    "admin/dispatch",
    "admin/payments",
    "admin/proof",
    "admin/waitblock",
    "token=",
    "fumapgo_admin",
    "fgo_admin",
    "FUMAPGO_ADMIN",
)

ADMIN_INTENT_KEYWORDS = {
    "admin",
    "ops",
    "operator",
    "manager",
    "quản lý",
    "quan ly",
    "admin ops",
    "後台",
    "管理",
    "管理員",
    "管理员",
    "系統管理",
    "後台管理",
}


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def json_ok(**kwargs):
    return jsonify({"ok": True, **kwargs})


def json_fail(message, status_code=400, **kwargs):
    return jsonify({"ok": False, "error": message, **kwargs}), status_code


def safe_support_text():
    return (
        "已收到訊息。\n\n"
        "FumapGo LINE 目前作為通知與客服入口使用。\n"
        "如需處理訂單、付款、外送或管理功能，請回到 FumapGo Webapp。\n\n"
        f"Marketplace:\n{PUBLIC_MARKETPLACE_URL}\n\n"
        "系統或管理問題請聯絡 Email:\n"
        f"{ADMIN_CONTACT_EMAIL}"
    )


def sanitize_line_text(text: str) -> str:
    """
    P0 guardrail:
    Any outgoing LINE text containing admin path/token is replaced.
    This protects both reply_message and internal push_message.
    """
    raw = str(text or "")
    low = raw.lower()

    for key in DANGEROUS_LINE_TEXT_KEYS:
        if key.lower() in low:
            print(
                "[SECURITY] blocked dangerous LINE text containing admin/token",
                flush=True,
            )
            return safe_support_text()

    return raw


def line_headers(content_type="application/json"):
    headers = {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
    }

    if content_type:
        headers["Content-Type"] = content_type

    return headers


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
    safe_text = sanitize_line_text(text)
    return {
        "type": "text",
        "text": str(safe_text or "")[:5000],
    }


def image_message(image_url, preview_url=""):
    preview_url = preview_url or image_url

    return {
        "type": "image",
        "originalContentUrl": image_url,
        "previewImageUrl": preview_url,
    }


def sanitize_messages(messages):
    safe = []

    for msg in messages or []:
        if not isinstance(msg, dict):
            safe.append(text_message(str(msg)))
            continue

        if msg.get("type") == "text":
            msg = dict(msg)
            msg["text"] = sanitize_line_text(msg.get("text", ""))
            safe.append(msg)
            continue

        safe.append(msg)

    return safe


def reply_message(reply_token, messages):
    if not LINE_CHANNEL_ACCESS_TOKEN:
        return {"ok": False, "error": "LINE_CHANNEL_ACCESS_TOKEN not set"}

    if not reply_token:
        return {"ok": False, "error": "reply_token missing"}

    payload = {
        "replyToken": reply_token,
        "messages": sanitize_messages(messages)[:5],
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

    if str(to).upper() == "ADMIN":
        return {
            "ok": True,
            "skipped": True,
            "reason": "P0 security: admin LINE push disabled. Use admin email.",
            "admin_contact_email": ADMIN_CONTACT_EMAIL,
        }

    payload = {
        "to": to,
        "messages": sanitize_messages(messages)[:5],
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


def normalize_web_role(role):
    role = (role or "customer").lower().strip()

    if role in ("shipper", "driver"):
        return "driver"

    if role in ("shop", "store"):
        return "store"

    # P0 security: LINE must not create admin entry URLs.
    if role == "admin":
        return "customer"

    return "customer"


def web_line_bind_url(role, line_user_id=""):
    """
    Account-first LINE bind.

    Do not open old MVP /line/register directly as a public registration form.
    Always send user through webapp login first. After login, /line/register
    binds LINE to the currently logged-in account/role.
    """
    role = normalize_web_role(role)
    role_q = quote_plus(role)
    line_user_id_q = quote_plus(line_user_id or "")

    next_path = (
        f"/line/register"
        f"?role={role_q}"
        f"&line_user_id={line_user_id_q}"
        f"&view=mobile"
        f"&lang=zh"
    )

    return (
        f"{FGO_BASE_URL}/login"
        f"?next={quote_plus(next_path)}"
        f"&view=mobile"
        f"&lang=zh"
    )


def web_register_url(role, line_user_id=""):
    role = normalize_web_role(role)

    if role == "store":
        return f"{FGO_BASE_URL}/store/register?view=mobile&lang=zh"

    if role == "driver":
        return f"{FGO_BASE_URL}/driver/register?view=mobile&lang=zh"

    return f"{FGO_BASE_URL}/login?view=mobile&lang=zh"


def menu_text(user_id=""):
    customer_bind = web_line_bind_url("customer", user_id)
    store_bind = web_line_bind_url("store", user_id)
    driver_bind = web_line_bind_url("driver", user_id)

    return (
        "FumapGo LINE 通知中心\n\n"
        "正式規則：\n"
        "Webapp = 註冊 / 下單 / 上傳照片 / 營運\n"
        "LINE = 推送通知 / 客服 / 回到 webapp\n\n"
        "【LINE 綁定】\n"
        "請先在 webapp 建立帳號並登入，再從 Menu 進入 LINE 綁定。\n"
        "店家與外送員：LINE 綁定後等待 Admin 審核；Admin 不會替本人簽約。\n"
        "客戶：登入後可綁定 LINE 以接收訂單通知。\n\n"
        f"客戶登入後綁定 LINE：{customer_bind}\n"
        f"店家登入後綁定 LINE：{store_bind}\n"
        f"外送員登入後綁定 LINE：{driver_bind}\n\n"
        "【建立帳號】\n"
        f"店家註冊：{web_register_url('store', user_id)}\n"
        f"外送員註冊：{web_register_url('driver', user_id)}\n"
        f"登入：{FGO_BASE_URL}/login?view=mobile&lang=zh\n\n"
        "【主要入口】\n"
        f"Marketplace：{PUBLIC_MARKETPLACE_URL}\n"
        f"店家工作台：{FGO_BASE_URL}/store?view=mobile&lang=zh\n"
        f"外送員工作台：{FGO_BASE_URL}/driver?view=mobile&lang=zh\n"
        f"客服：{FGO_BASE_URL}/support/new?view=mobile&lang=zh\n\n"
        "系統或管理問題請聯絡 Email:\n"
        f"{ADMIN_CONTACT_EMAIL}\n\n"
        "可輸入：\n"
        "menu\n"
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
                "⏳ 你的帳號正在等待審核\n\n"
                f"角色：{role_label(role)}\n"
                f"狀態：{status} / {approval}\n"
                f"LINE User ID：{user_id}\n\n"
                f"查看狀態：{body.get('pending_url') or web_line_bind_url(role, user_id)}"
            )

    return (
        "你目前還沒有完成 LINE 綁定。\n\n"
        "正式流程：先建立 webapp 帳號並登入，再從 Menu 進入 LINE 綁定。\n\n"
        f"客戶登入後綁定 LINE：{web_line_bind_url('customer', user_id)}\n"
        f"店家登入後綁定 LINE：{web_line_bind_url('store', user_id)}\n"
        f"外送員登入後綁定 LINE：{web_line_bind_url('driver', user_id)}\n\n"
        "建立帳號：\n"
        f"店家註冊：{web_register_url('store', user_id)}\n"
        f"外送員註冊：{web_register_url('driver', user_id)}\n"
        f"登入：{FGO_BASE_URL}/login?view=mobile&lang=zh\n\n"
        f"LINE User ID：{user_id}"
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
            lines.append(
                f"店家：{binding.get('store_code')} / {binding.get('bound_store_name') or ''}"
            )

        if binding.get("driver_code"):
            lines.append(
                f"外送員：{binding.get('driver_code')} / {binding.get('bound_driver_name') or ''}"
            )

        if binding.get("approval_note"):
            lines.append(f"備註：{binding.get('approval_note')}")

        return "\n".join(lines)

    return (
        "尚未綁定 LINE 身份。\n\n"
        "請先登入 webapp，再綁定 LINE。\n\n"
        f"客戶登入後綁定 LINE：{web_line_bind_url('customer', user_id)}\n"
        f"店家登入後綁定 LINE：{web_line_bind_url('store', user_id)}\n"
        f"外送員登入後綁定 LINE：{web_line_bind_url('driver', user_id)}\n\n"
        f"LINE User ID：{user_id}"
    )


def forward_customer_service_to_admin(user_id, text="", event_type="text"):
    """
    P0 security:
    Do not forward CSKH to admin LINE.
    Log only. User receives admin email in LINE reply.
    """
    profile = get_line_profile(user_id)
    name = profile.get("displayName", "")

    print(
        "[LINE_CSKH]"
        f" user={name or '-'}"
        f" line_user_id={user_id}"
        f" type={event_type}"
        f" time={now_iso()}"
        f" message={str(text or '-')[:1000]}",
        flush=True,
    )

    return {
        "ok": True,
        "skipped_line_admin_push": True,
        "admin_contact_email": ADMIN_CONTACT_EMAIL,
    }


def is_admin_intent(raw: str) -> bool:
    text = (raw or "").strip()
    low = text.lower()

    if low in ADMIN_INTENT_KEYWORDS:
        return True

    return any(k in low for k in ADMIN_INTENT_KEYWORDS if k.isascii())


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

    if is_admin_intent(raw):
        forward_customer_service_to_admin(user_id, raw, event_type="admin_intent_blocked")
        return reply_message(reply_token, [text_message(safe_support_text())])

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
                    "如需系統或管理協助，請聯絡 Email:\n"
                    f"{ADMIN_CONTACT_EMAIL}\n\n"
                    "若是訂單問題，請附上訂單碼。"
                )
            ],
        )

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
                    f"客戶登入後綁定 LINE：{web_line_bind_url('customer', user_id)}\n"
                    f"店家登入後綁定 LINE：{web_line_bind_url('store', user_id)}\n"
                    f"外送員登入後綁定 LINE：{web_line_bind_url('driver', user_id)}"
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
                f"Marketplace：{PUBLIC_MARKETPLACE_URL}\n\n"
                "系統或管理問題請聯絡 Email:\n"
                f"{ADMIN_CONTACT_EMAIL}\n\n"
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
        module="FumapGo LINE Notification Gateway",
        mode=APP_MODE,
        fgo_base_url=FGO_BASE_URL,
        line_token_set=bool(LINE_CHANNEL_ACCESS_TOKEN),
        line_secret_set=bool(LINE_CHANNEL_SECRET),
        internal_secret_set=bool(FGO_INTERNAL_SECRET),
        admin_line_env_set=bool(FGO_ADMIN_LINE_USER_ID),
        admin_line_push_enabled=False,
        admin_contact_email=ADMIN_CONTACT_EMAIL,
        public_marketplace_url=PUBLIC_MARKETPLACE_URL,
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
        return json_ok(
            skipped=True,
            reason="P0 security: admin LINE push disabled. Use admin email.",
            admin_contact_email=ADMIN_CONTACT_EMAIL,
        )

    text = str(payload.get("text") or payload.get("message") or "").strip()
    text = sanitize_line_text(text)

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
        return json_ok(
            skipped=True,
            reason="P0 security: admin LINE image push disabled. Use admin email.",
            admin_contact_email=ADMIN_CONTACT_EMAIL,
        )

    image_url = str(
        payload.get("image_url") or payload.get("public_image_url") or ""
    ).strip()
    preview_url = str(
        payload.get("preview_url") or payload.get("preview_image_url") or image_url
    ).strip()
    text = str(payload.get("text") or payload.get("message") or "").strip()
    text = sanitize_line_text(text)

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
    """
    Compatibility endpoint.

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
        or ""
    ).strip()

    if line_user_id.upper() == "ADMIN":
        return json_ok(
            skipped=True,
            reason="P0 security: admin LINE photo-session push disabled.",
            admin_contact_email=ADMIN_CONTACT_EMAIL,
        )

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
                                f"Marketplace：{PUBLIC_MARKETPLACE_URL}\n"
                                f"客服：{FGO_BASE_URL}/support/new?view=mobile&lang=zh\n\n"
                                "系統或管理問題請聯絡 Email:\n"
                                f"{ADMIN_CONTACT_EMAIL}"
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
                                "輸入 menu 可查看入口。\n\n"
                                f"Marketplace：{PUBLIC_MARKETPLACE_URL}"
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

            # P0 security: do not push callback error to admin LINE.
            print(
                "[LINEHOOK_ERROR]"
                f" error={e}"
                f" time={now_iso()}"
                f" admin_contact_email={ADMIN_CONTACT_EMAIL}",
                flush=True,
            )

    return "OK"
