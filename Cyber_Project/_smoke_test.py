
"""
_smoke_test.py – temporary startup smoke test (delete after Step 2).
Starts Flask on port 5000, GETs /login, then shuts down cleanly.
"""
import sys, threading, time, urllib.request, urllib.error

sys.path.insert(0, ".")

from app import create_app
import werkzeug.serving

app = create_app()

server = werkzeug.serving.make_server("127.0.0.1", 5000, app)
t = threading.Thread(target=server.serve_forever)
t.daemon = True
t.start()
time.sleep(1.5)  # allow socket to bind

try:
    resp = urllib.request.urlopen("http://127.0.0.1:5000/login", timeout=5)
    body = resp.read().decode()
    print(f"[OK] GET /login -> HTTP {resp.status}")
    marker = "SecureMed"
    if marker in body:
        print(f"[OK] Response contains '{marker}' — login page rendered correctly.")
    else:
        print("[WARN] Expected text not found in body.")
except urllib.error.URLError as e:
    print(f"[FAIL] Could not reach server: {e}")
    sys.exit(1)
finally:
    server.shutdown()
    print("[OK] Server shut down cleanly.")
