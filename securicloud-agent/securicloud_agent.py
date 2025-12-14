import contextlib
import os
import secrets
import ssl
import requests
import asyncio
import json
import signal
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import urllib.parse

DEBUG = os.getenv("SECURICLOUD_AGENT_DEBUG", "false").lower() == "true"
TUNNEL_HOST = "securicloud.me"
TUNNEL_PORT = 5001
# TUNNEL_HOST = "tunnel.securicloud.me"
# TUNNEL_PORT = 443

REDIRECT_PORT = 8099  # ingress will forward to this

stopping = asyncio.Event()
_live = set()
_httpd = None

ssl_ctx = ssl.create_default_context()


# -----------------------------------------------------------------------------
# LOGGING UTILITIES
# -----------------------------------------------------------------------------

def log(msg: str):
    print(msg)

def debug(msg: str):
    if DEBUG:
        print("[DEBUG]", msg)


# -----------------------------------------------------------------------------
# SUPERVISOR RESTART
# -----------------------------------------------------------------------------

def restart_addon():
    """Triggers Supervisor-managed restart AFTER the reset UI is shown."""
    try:
        token = os.getenv("SUPERVISOR_TOKEN")
        if not token:
            log("[RESTART] No supervisor token!")
            return

        url = "http://supervisor/addons/self/restart"
        r = requests.post(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)

        if r.status_code == 200:
            log("[RESTART] Add-on restart triggered.")
        else:
            log(f"[RESTART] Failure: {r.status_code} {r.text}")

    except Exception as e:
        log(f"[RESTART] Exception: {e}")


# -----------------------------------------------------------------------------
# ASYNC UTIL
# -----------------------------------------------------------------------------

def spawn(coro):
    task = asyncio.create_task(coro)
    _live.add(task)
    task.add_done_callback(lambda t: (_live.discard(t), debug(f"Live tasks: {len(_live)}")))
    return task


# -----------------------------------------------------------------------------
# SIGNAL HANDLING
# -----------------------------------------------------------------------------

def handle_stop(*_):
    log("Received stop signal → shutting down")
    stopping.set()
    stop_ingress_redirect_server()


# -----------------------------------------------------------------------------
# DISCOVER HOME ASSISTANT
# -----------------------------------------------------------------------------

def discover_local_ha():
    api = os.getenv("SUPERVISOR_API")
    token = os.getenv("SUPERVISOR_TOKEN")

    if api and token:
        try:
            r = requests.get(
                f"{api}/core/info",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            d = r.json().get("data", {})
            return d.get("host", "127.0.0.1"), int(d.get("port", 8123))
        except Exception as e:
            log(f"Supervisor lookup failed: {e}")

    return "127.0.0.1", 8123


# -----------------------------------------------------------------------------
# INSTANCE ID FILE
# -----------------------------------------------------------------------------

def get_ha_instance_id():
    path = Path("/share/ha_instance_id.json")
    try:
        if path.exists():
            try:
                return json.loads(path.read_text())["instance_id"]
            except Exception:
                pass

        # generate 25-char base36 ID
        base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
        new_id = ''.join(secrets.choice(base36) for _ in range(25))
        path.write_text(json.dumps({"instance_id": new_id}))
        return new_id

    except Exception:
        return "test1"


# -----------------------------------------------------------------------------
# TUNNEL CODE (unchanged)
# -----------------------------------------------------------------------------

async def pipe_tunnel_to_ha(t_reader, t_writer, ha_writer, first_chunk):
    try:
        length = int.from_bytes(first_chunk)
        while not stopping.is_set():
            if length > 0:
                d = await t_reader.readexactly(length)
                ha_writer.write(d)
                await ha_writer.drain()

            while not stopping.is_set():
                try:
                    b = await asyncio.wait_for(t_reader.readexactly(2), 5)
                    length = int.from_bytes(b)
                    break
                except asyncio.TimeoutError:
                    t_writer.write(b"\x00\x00")
                    await t_writer.drain()

    except asyncio.CancelledError:
        pass
    except Exception:
        pass

    finally:
        if not ha_writer.is_closing():
            ha_writer.close()
            with contextlib.suppress(Exception):
                await ha_writer.wait_closed()


async def pipe_ha_to_tunnel(ha_reader, t_writer):
    try:
        while not stopping.is_set():
            d = await ha_reader.read(8192)
            if not d:
                break
            t_writer.write(len(d).to_bytes(2, "big"))
            t_writer.write(d)
            await t_writer.drain()

    except asyncio.CancelledError:
        pass
    except Exception:
        pass

    finally:
        if not t_writer.is_closing():
            t_writer.close()
            with contextlib.suppress(Exception):
                await t_writer.wait_closed()


async def handle_active_connection(t_reader, t_writer, first_chunk):
    ha_reader = ha_writer = None

    try:
        debug("[FORWARD] Opening HA connection…")
        ha_reader, ha_writer = await asyncio.open_connection(LOCAL_HA[0], LOCAL_HA[1])

        t1 = spawn(pipe_tunnel_to_ha(t_reader, t_writer, ha_writer, first_chunk))
        t2 = spawn(pipe_ha_to_tunnel(ha_reader, t_writer))

        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for p in pending:
            p.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    except Exception as e:
        log(f"[FORWARD] Error: {e}")

    finally:
        for w in (t_writer, ha_writer):
            if w:
                with contextlib.suppress(Exception):
                    w.close()
                    await w.wait_closed()

        debug("[FORWARD] Session closed")


async def keep_idle_connection(print_conn_logs):
    while not stopping.is_set():
        try:
            if print_conn_logs or DEBUG:
                log(f"[IDLE] Connecting to {TUNNEL_HOST}:{TUNNEL_PORT}")

            r, w = await asyncio.open_connection(
                TUNNEL_HOST,
                int(TUNNEL_PORT),
                ssl=ssl_ctx,
                server_hostname=TUNNEL_HOST
            )

            ident = HA_INSTANCE_ID.encode()
            w.write(len(ident).to_bytes(2, "big"))
            w.write(ident)
            await w.drain()

            if print_conn_logs or DEBUG:
                log("[IDLE] Connected. The service is running…")
            print_conn_logs = False

            while not stopping.is_set():
                try:
                    first_chunk = await asyncio.wait_for(r.readexactly(2), 5)
                    break
                except asyncio.TimeoutError:
                    w.write(b"\x00\x00")
                    await w.drain()

            if not first_chunk or stopping.is_set():
                w.close()
                await asyncio.sleep(1)
                continue

            spawn(keep_idle_connection(False))
            await handle_active_connection(r, w, first_chunk)
            break

        except Exception as e:
            log(f"[IDLE] Error: {e}, retrying in 3s")
            print_conn_logs = True
            await asyncio.sleep(3)


# -----------------------------------------------------------------------------
# INGRESS UI (polished)
# -----------------------------------------------------------------------------

class RedirectHandler(BaseHTTPRequestHandler):

    # FULL POLISHED MAIN PAGE -------------------------------------------------

    def build_main_page(self) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Securicloud Agent</title>
<link rel="stylesheet"
 href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body>

<div class="container" style="max-width:650px; margin-top:40px;">

  <div class="card shadow-sm">
    <div class="card-header bg-primary text-white">
      <h4 class="mb-0">Securicloud</h4>
      <p class="text-white small mb-0">
        Secure remote access for Home Assistant
      </p>
    </div>

    <div class="card-body">

      <p class="text-muted mb-4">
        Manage your Securicloud remote-access for this Home Assistant instance.
      </p>

      <label class="fw-semibold mb-1">Instance ID</label>
      <div class="input-group mb-3">
        <input type="text" class="form-control" readonly value="{HA_INSTANCE_ID}">
      </div>

      <button class="btn btn-success w-100 mb-3"
              onclick="window.top.open('{regAgentUrl}', '_blank')">
        Register Installation
      </button>

      <button class="btn btn-secondary w-100"
              onclick="window.top.open('{controlPanelUrl}', '_blank')">
        Securicloud Control Panel
      </button>

      <hr>

      <div class="alert alert-danger small">
        Resetting the Instance ID will immediately revoke all
        existing remote access and invalidate all Access Tokens
        associated with this Home Assistant installation.
      </div>

      <button class="btn btn-danger w-100"
              hx-get="reset-confirm"
              hx-target="body"
              hx-swap="innerHTML">
        Reset Instance ID
      </button>

    </div>
  </div>
</div>

</body>
</html>
"""
    
    # CONFIRMATION PAGE -------------------------------------------------------

    def build_confirm_page(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Confirm Instance ID Reset</title>
<link rel="stylesheet"
 href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body>

<div class="container" style="max-width:650px; margin-top:60px;">
  <div class="card border-warning shadow-sm">
    <div class="card-header bg-warning">
      <strong>Confirm Instance ID Reset</strong>
    </div>

    <div class="card-body">
      <p>
        This action will permanently invalidate the current
        <b>Instance ID</b> for this Home Assistant installation.
      </p>

      <p class="text-danger">
        All active remote access sessions will be terminated and
        all Access Tokens currently associated with this installation
        will be revoked.
      </p>

      <p>
        A new Instance ID will be generated automatically
        after the add-on restarts.
      </p>

      <div class="d-flex justify-content-between mt-4">
        <button class="btn btn-secondary"
                hx-get="."
                hx-target="body"
                hx-swap="innerHTML">
          Cancel
        </button>

        <button class="btn btn-danger"
                hx-get="reset-now"
                hx-target="body"
                hx-swap="innerHTML">
          Reset Instance ID
        </button>
      </div>
    </div>
  </div>
</div>

</body>
</html>
"""

    # RESET PAGE WITH AUTO-REFRESH -------------------------------------------

    def build_reset_done_page(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Restarting Securicloud Agent</title>
<link rel="stylesheet"
 href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
</head>

<body>

<script>
async function checkAlive() {
    try {
        const r = await fetch(window.location.href, { cache: "no-store" });
        if (r.ok) {
            window.location.reload();
        }
    } catch (e) {}
}
setInterval(checkAlive, 3000);
</script>

<div class="container" style="max-width:650px; margin-top:60px;">
  <div class="alert alert-warning text-center shadow-sm">
    <h4>Instance ID Reset</h4>
    <p>The previous Instance ID has been revoked.</p>
    <p>A new Instance ID will be generated during startup.</p>
    <hr>
    <p>
      The Securicloud Agent is restarting.<br>
      This page will refresh automatically when the service is ready.
    </p>
  </div>
</div>

</body>
</html>
"""

    # -------------------------------------------------------------------------
    # ROUTING
    # -------------------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        clean = parsed.path.rstrip("/")

        if clean.endswith("reset-confirm"):
            return self.respond_html(self.build_confirm_page())

        if clean.endswith("reset-now"):
            return self.handle_reset_now()

        if clean.endswith("check-ready"):
            return self.respond_html(self.build_reset_done_page())

        # MAIN PAGE
        return self.respond_html(self.build_main_page())

    # -------------------------------------------------------------------------

    def respond_html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -------------------------------------------------------------------------

    def handle_reset_now(self):
        """Delete ID file, show restart page, trigger restart."""
        try:
            p = Path("/share/ha_instance_id.json")
            if p.exists():
                p.unlink()
            log("[RESET] Instance ID file deleted.")
        except Exception as e:
            log(f"[RESET] Error deleting file: {e}")

        # Show restart UI first
        self.respond_html(self.build_reset_done_page())

        # Restart in background
        threading.Thread(target=restart_addon, daemon=True).start()

    def log_message(self, *args):
        return  # silence HTTP logs


# -----------------------------------------------------------------------------
# INGRESS SERVER
# -----------------------------------------------------------------------------

def start_ingress_redirect_server():
    global _httpd
    try:
        log(f"[INGRESS] Starting admin UI on {REDIRECT_PORT}")
        _httpd = HTTPServer(("0.0.0.0", REDIRECT_PORT), RedirectHandler)
        log("[INGRESS] Ready")
        _httpd.serve_forever()
    except Exception as e:
        log(f"[INGRESS] Failed to start admin UI: {e}")


def stop_ingress_redirect_server():
    global _httpd
    if _httpd:
        with contextlib.suppress(Exception):
            log("[INGRESS] Shutting down admin UI")
            _httpd.shutdown()


# -----------------------------------------------------------------------------
# MAIN ASYNC ENTRY
# -----------------------------------------------------------------------------

async def main():
    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    log(f"[INFO] Instance registration URL: {regAgentUrl}")

    threading.Thread(target=start_ingress_redirect_server, daemon=True).start()
    spawn(keep_idle_connection(True))

    await asyncio.Event().wait()


# -----------------------------------------------------------------------------
# STARTUP
# -----------------------------------------------------------------------------

LOCAL_HA = discover_local_ha()
HA_INSTANCE_ID = get_ha_instance_id()
regAgentUrl = f"https://securicloud.me/add-agent/home_assistant/{HA_INSTANCE_ID}"
controlPanelUrl = f"https://securicloud.me/portal"

asyncio.run(main())
