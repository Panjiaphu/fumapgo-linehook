import os
import hmac
import base64
import hashlib
import json
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "")
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_CHANNEL_ID = os.getenv("LINE_CHANNEL_ID", "")
FGO_BASE_URL = os.getenv("FGO_BASE_URL", "https://fumapgo.onrender.com").rstrip("/")
FGO_INTERNAL_SECRET = os.getenv("FGO_INTERNAL_SECRET", "")
APP_MODE = os.getenv("APP_MODE", "fumapgo")

LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def line_headers():
    return {
        "Authorization": f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }


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
        return {"ok": False, "error": "missing token"}
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


@app.get("/")
def index():
    return jsonify({"ok": True, "app": "fumapgo-linehook", "mode": APP_MODE, "time": now_iso()})


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
            text = (message.get("text") or "").strip().lower()

            if text in ["ping", "test", "測試"]:
                reply_message(reply_token, [text_message(
                    "pong ✅\n"
                    "FUMAP GO LINE webhook 已連線。\n"
                    f"User ID：{user_id}"
                )])
            elif text in ["menu", "選單", "功能", "開始", "start"]:
                reply_message(reply_token, [text_message(menu_text(user_id))])
            elif text.startswith("bind"):
                reply_message(reply_token, [text_message(
                    "綁定功能準備中。\n"
                    "下一步支援：bind driver / bind store / bind customer。\n"
                    f"你的 LINE User ID：{user_id}"
                )])
            else:
                reply_message(reply_token, [text_message(
                    "已收到訊息。\n"
                    "請輸入「menu」查看 FUMAP GO 功能，或使用下方圖文選單。"
                )])

        elif event_type == "message" and message_type == "image":
            message_id = message.get("id", "")
            reply_message(reply_token, [text_message(
                "已收到照片 ✅\n"
                "Photo Proof Automation 準備中。\n"
                "之後系統會自動綁定訂單、保存至 Google Drive，並建立 PHOTO_DELIVERY_BLOCK。\n\n"
                f"LINE messageId：{message_id}"
            )])

        elif event_type == "postback":
            reply_message(reply_token, [text_message("已收到操作。")])

    return "OK", 200


@app.post("/internal/push")
def internal_push():
    secret = request.headers.get("X-FGO-INTERNAL-SECRET", "")
    if FGO_INTERNAL_SECRET and secret != FGO_INTERNAL_SECRET:
        abort(403, "Forbidden")

    payload = request.get_json(silent=True) or {}
    to = payload.get("to") or payload.get("line_user_id")
    text = payload.get("text") or "FUMAP GO notification"
    result = push_message(to, [text_message(text)])
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
