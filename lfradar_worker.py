"""
LF RADAR — Telegram source-account monitoring worker (Telethon)

Runs 24/7 on your own server/VPS (Railway, Fly.io, Render, a VPS…). It:
  * logs in as the authorized Telegram USER account (login code + 2FA entered from the dashboard)
  * keeps the session encrypted on disk (AES-256-CTR + HMAC-SHA256, encrypt-then-MAC)
  * reports groups the account can access and a heartbeat every few seconds
  * forwards new messages from groups enabled in the dashboard to LF RADAR (signed with a shared secret)
  * never posts anything into groups

Requirements:  pip install telethon==1.36.0 requests
  (no `cryptography` needed — AES comes from `pyaes`, which Telethon installs itself;
   HMAC/SHA-256 come from the Python standard library)
Environment variables:
  TG_API_ID, TG_API_HASH   -> from https://my.telegram.org (keep private, never put them in the website)
  TG_PHONE                 -> phone number of the authorized source account, e.g. +639171234567
  LFRADAR_SYNC_URL         -> webhook URL of the `workerSync` workflow
  LFRADAR_INGEST_URL       -> webhook URL of the `workerIngest` workflow
  LFRADAR_SECRET           -> same value as the ZITE_WORKER_SECRET secret in LF RADAR
  SESSION_FILE (optional)  -> default ./lfradar.session.enc
"""
import asyncio, base64, hashlib, hmac, json, logging, os, sys, time
import requests
from telethon import TelegramClient, events, errors
from telethon.sessions import StringSession

try:
    import pyaes  # hard dependency of Telethon, so it is present wherever Telethon is installed
except ImportError:
    sys.exit("LF RADAR worker: the `pyaes` module (installed with Telethon) is missing, so the session "
             "and login codes cannot be encrypted. Refusing to start rather than storing them in plaintext.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("lfradar")

_REQUIRED = ["TG_API_ID", "TG_API_HASH", "TG_PHONE", "LFRADAR_SYNC_URL", "LFRADAR_INGEST_URL", "LFRADAR_SECRET"]
_missing = [k for k in _REQUIRED if not os.environ.get(k, "").strip()]
if _missing:
    sys.exit("LF RADAR worker: missing settings: " + ", ".join(_missing) + " — add them in Railway → Variables.")
if not os.environ["TG_API_ID"].strip().isdigit():
    sys.exit("LF RADAR worker: TG_API_ID must be the numeric API ID from my.telegram.org.")
if "<" in os.environ["LFRADAR_SECRET"]:
    sys.exit("LF RADAR worker: LFRADAR_SECRET still has the placeholder — paste your real ZITE_WORKER_SECRET value.")

API_ID = int(os.environ["TG_API_ID"].strip())
API_HASH = os.environ["TG_API_HASH"].strip()
PHONE = os.environ["TG_PHONE"].strip()
SYNC_URL = os.environ["LFRADAR_SYNC_URL"].strip()
INGEST_URL = os.environ["LFRADAR_INGEST_URL"].strip()
SECRET = os.environ["LFRADAR_SECRET"].strip()
SESSION_FILE = os.environ.get("SESSION_FILE", "lfradar.session.enc")
if os.path.dirname(SESSION_FILE):
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
log.info("LF RADAR worker starting (session file: %s)", SESSION_FILE)
HEADERS = {"content-type": "application/json", "x-lfradar-secret": SECRET}


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# Separate encryption / authentication keys derived from the shared secret (must match server/telegram.ts).
ENC_KEY = _hmac(SECRET.encode(), b"lfradar-enc-v2")
MAC_KEY = _hmac(SECRET.encode(), b"lfradar-mac-v2")
MAGIC = b"v2"


def _ctr(iv: bytes, data: bytes) -> bytes:
    # AES-256-CTR via pyaes (the AES implementation Telethon itself ships with).
    ctr = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
    return pyaes.AESModeOfOperationCTR(ENC_KEY, counter=ctr).encrypt(data)


def seal(plain: bytes) -> bytes:
    """AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC). Layout: v2 | iv(16) | ciphertext | tag(32)."""
    iv = os.urandom(16)
    head = MAGIC + iv + _ctr(iv, plain)
    return head + _hmac(MAC_KEY, head)


def open_sealed(raw: bytes) -> bytes:
    if len(raw) < 2 + 16 + 32 or raw[:2] != MAGIC:
        raise ValueError("unsupported or corrupted ciphertext")
    head, tag = raw[:-32], raw[-32:]
    if not hmac.compare_digest(tag, _hmac(MAC_KEY, head)):
        raise ValueError("authentication failed (wrong secret or tampered data)")
    return _ctr(head[2:18], head[18:])


def decrypt(b64: str) -> str:
    return open_sealed(base64.b64decode(b64)).decode()


def save_session(s: str):
    tmp = SESSION_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(seal(s.encode()))
    os.replace(tmp, SESSION_FILE)


def load_session() -> str:
    try:
        with open(SESSION_FILE, "rb") as f:
            raw = f.read()
        return open_sealed(raw).decode()
    except FileNotFoundError:
        return ""
    except Exception as e:
        log.error("Could not decrypt session file (%s). If it was written by an older worker version "
                  "(AES-GCM format) or the secret changed, reconnect from Source Accounts — starting fresh.", e)
        return ""


def post(url: str, body: dict, tries: int = 4):
    delay = 2
    for i in range(tries):
        try:
            r = requests.post(url, data=json.dumps(body), headers=HEADERS, timeout=30)
            if r.status_code == 401:
                log.error("LF RADAR rejected the worker secret (401). Check LFRADAR_SECRET.")
                return None
            if r.ok:
                data = r.json() if r.content else {}
                # tolerate wrapped responses
                for k in ("output", "result", "data"):
                    if isinstance(data, dict) and isinstance(data.get(k), dict) and "command" in data[k]:
                        return data[k]
                return data
            log.warning("POST %s -> %s %s", url.split("/webhooks/")[-1].split("/")[0], r.status_code, r.text[:200])
        except requests.RequestException as e:
            log.warning("Network error: %s", e)
        time.sleep(delay)
        delay = min(delay * 2, 30)
    return None


class Worker:
    def __init__(self):
        self.client = TelegramClient(StringSession(load_session()), API_ID, API_HASH, catch_up=True)
        self.status = "Not Connected"
        self.error = ""
        self.phone_code_hash = None
        self.monitored: set[str] = set()
        self.me = None
        self.outbox: list[dict] = []
        self.send_groups = False
        self.group_errors: list[dict] = []

    async def ensure_connected(self):
        if not self.client.is_connected():
            await self.client.connect()

    async def finish_login(self):
        self.me = await self.client.get_me()
        save_session(self.client.session.save())
        self.status, self.error, self.send_groups = "Connected", "", True
        log.info("Connected as %s", self.me.id)

    async def handle_command(self, cmd: str, payload: str):
        try:
            if cmd in ("Start Login", "Reconnect"):
                await self.ensure_connected()
                if await self.client.is_user_authorized():
                    await self.finish_login()
                else:
                    sent = await self.client.send_code_request(PHONE)
                    self.phone_code_hash = sent.phone_code_hash
                    self.status, self.error = "Awaiting Code", ""
            elif cmd == "Submit Code":
                await self.ensure_connected()
                try:
                    await self.client.sign_in(PHONE, decrypt(payload), phone_code_hash=self.phone_code_hash)
                    await self.finish_login()
                except errors.SessionPasswordNeededError:
                    self.status = "Awaiting Password"
            elif cmd == "Submit Password":
                await self.ensure_connected()
                await self.client.sign_in(password=decrypt(payload))
                await self.finish_login()
            elif cmd == "Refresh Groups":
                self.send_groups = True
            elif cmd == "Disconnect":
                if self.client.is_connected() and await self.client.is_user_authorized():
                    await self.client.log_out()
                if os.path.exists(SESSION_FILE):
                    os.remove(SESSION_FILE)
                self.client = TelegramClient(StringSession(), API_ID, API_HASH, catch_up=True)
                self.register_handlers()
                self.status, self.me, self.error = "Disconnected", None, ""
        except (errors.PhoneCodeInvalidError, errors.PhoneCodeExpiredError) as e:
            self.status, self.error = "Awaiting Code", f"Login code rejected: {type(e).__name__}. Click Reconnect for a new code."
        except errors.PasswordHashInvalidError:
            self.status, self.error = "Awaiting Password", "Two-step verification password was incorrect."
        except errors.FloodWaitError as e:
            self.status, self.error = "Error", f"Telegram rate limit: wait {e.seconds}s before retrying."
        except Exception as e:  # never include secrets in the message
            self.status, self.error = "Error", f"{type(e).__name__}: {str(e)[:300]}"

    async def list_groups(self):
        groups = []
        async for d in self.client.iter_dialogs():
            if d.is_group or d.is_channel:
                kind = "Supergroup" if getattr(d.entity, "megagroup", False) else ("Channel" if d.is_channel else "Group")
                groups.append({"chatId": str(d.id), "title": d.name or str(d.id), "type": kind})
        return groups

    def register_handlers(self):
        async def on_msg(event, edited=False):
            chat_id = str(event.chat_id)
            if chat_id not in self.monitored or not event.raw_text:
                return
            self.outbox.append({
                "chatId": chat_id, "messageId": str(event.id), "text": event.raw_text[:8000],
                "date": event.date.isoformat() if event.date else None,
                "senderId": str(event.sender_id) if event.sender_id else None, "edited": edited,
            })

        self.client.add_event_handler(lambda e: on_msg(e, False), events.NewMessage(incoming=True))
        self.client.add_event_handler(lambda e: on_msg(e, True), events.MessageEdited(incoming=True))

    async def sync_loop(self):
        while True:
            body = {"status": self.status, "error": self.error}
            if self.me:
                body.update(accountId=str(self.me.id), displayName=" ".join(filter(None, [self.me.first_name, self.me.last_name])) or (self.me.username or ""),
                            phoneHint=("•••" + (self.me.phone or "")[-4:]) if self.me.phone else "")
            if self.send_groups and self.status == "Connected":
                try:
                    body["groups"] = await self.list_groups()
                    self.send_groups = False
                except Exception as e:
                    self.error = f"Group refresh failed: {e}"
            if self.group_errors:
                body["groupErrors"], self.group_errors = self.group_errors[:50], []
            res = await asyncio.to_thread(post, SYNC_URL, body)
            if res:
                self.monitored = set(res.get("monitoredChatIds") or [])
                cmd = res.get("command") or "None"
                if cmd != "None":
                    log.info("Command: %s", cmd)
                    await self.handle_command(cmd, res.get("payload") or "")
            await asyncio.sleep(5)

    async def ingest_loop(self):
        while True:
            if self.outbox:
                batch, self.outbox = self.outbox[:50], self.outbox[50:]
                res = await asyncio.to_thread(post, INGEST_URL, {"messages": batch}, 6)
                if res is None:  # keep messages for the next attempt; server de-duplicates
                    self.outbox = batch + self.outbox
                    await asyncio.sleep(10)
            await asyncio.sleep(1)

    async def run(self):
        self.register_handlers()
        await self.ensure_connected()
        if await self.client.is_user_authorized():
            await self.finish_login()
        asyncio.create_task(self.ingest_loop())
        asyncio.create_task(self.sync_loop())
        while True:  # keep the client alive & reconnect after network failures
            try:
                await self.ensure_connected()
                if self.status == "Connected":
                    await self.client.run_until_disconnected()
                    log.warning("Disconnected from Telegram, reconnecting…")
                else:
                    await asyncio.sleep(2)
            except Exception as e:
                self.error = f"Connection error: {e}"
                await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(Worker().run())
