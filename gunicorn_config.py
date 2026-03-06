# gunicorn_config.py

'''
#if we use gunicorn allown
bind = "10.10.24.188:8000"  # IP and port
workers = 4                # number of worker processes
accesslog = "logs/access.log"  # access log file
errorlog = "logs/error.log"    # error log file
loglevel = "info"          # log level (debug, info, warning, error, critical)
daemon = True              # run in background
timeout = 120              # request timeout in seconds
'''

#if we use gunicorn with nginx
bind = "127.0.0.1:8000"           # Only listen on localhost
workers = 4                        # Good default for CPU cores
worker_class = "sync"              # Fine for CPU-heavy apps
timeout = 120                      # Requests timeout
accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"
max_requests = 1000                # Recycle workers to prevent memory leaks
max_requests_jitter = 50
forwarded_allow_ips = "*"          # Trust all proxies for X-Forwarded-For which is important to log the origin IP
daemon = False                     # Use systemd/supervisor to run in background
#access_log_format = '%({X-Forwarded-For}i)s - %(u)s [%(t)s] "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
"""
bind = "127.0.0.1:8000" — correct when Nginx is reverse proxying. Never bind Gunicorn directly to a public IP if behind Nginx.

forwarded_allow_ips = "*" — this ensures Gunicorn logs real client IP from X-Forwarded-For.

daemon = False — correct; don’t daemonize when using systemd.

Workers: 4 is fine for a small local setup; in production, you can calculate workers as 2 x CPU cores + 1.

max_requests + max_requests_jitter — good for avoiding memory leaks on long-running apps.


=========================to log the actual IP===========================
### Option A — Gunicorn’s `access_log_format`
# <-- This line forces Gunicorn to log real IPs
access_log_format = '%({X-Forwarded-For}i)s - %(u)s [%(t)s] "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
```

> Important: keep `forwarded_allow_ips = "*"` so Gunicorn **trusts the proxy** and doesn’t ignore `X-Forwarded-For`.

---

### Option B — Use WSGI middleware (`ProxyFix`) for Flask/Django

If your app uses **Flask** or **Django**, you can let the app itself rewrite `REMOTE_ADDR` from `X-Forwarded-For`.

**Flask example:**

```python
from werkzeug.middleware.proxy_fix import ProxyFix
app = create_app()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
```

* `x_for=1` → trust **one proxy** (your Nginx).
* `x_proto=1` → sets `wsgi.url_scheme` to the client protocol.
* Now `request.remote_addr` in Flask and Gunicorn’s log (with default format) will show **real IP**.

**Django example:**

```python
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
```
"""