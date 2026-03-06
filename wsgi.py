from app_main import create_app
from werkzeug.middleware.proxy_fix import ProxyFix #to preserve the origin IP during loging
app = create_app()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)