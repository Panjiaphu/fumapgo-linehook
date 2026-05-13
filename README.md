# FUMAP GO LINEHOOK

Clean LINE webhook server for FUMAP GO.

## Purpose

- LINE Official Account webhook `/callback`
- Basic text reply / ping test
- Image message receiving placeholder
- Future bridge to FGO webapp
- Future Google Drive photo proof automation

## Render

Build Command:

```bash
pip install -r requirements.txt
```

Start Command:

```bash
gunicorn main:app
```

Health Check Path:

```text
/health
```

Webhook URL:

```text
https://fumapgo-linehook.onrender.com/callback
```

## Required ENV

```env
APP_MODE=fumapgo
LINE_CHANNEL_ID=
LINE_CHANNEL_SECRET=
LINE_CHANNEL_ACCESS_TOKEN=
FGO_BASE_URL=https://fumapgo.onrender.com
FGO_INTERNAL_SECRET=
TZ=Asia/Taipei
```

## Test

Send `ping` to the LINE Official Account.

Expected reply:

```text
pong ✅
FUMAP GO LINE webhook 已連線。
```
