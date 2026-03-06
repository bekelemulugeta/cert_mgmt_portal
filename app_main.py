from flask import Flask
from config import Config
from models import (
    db, Admin, Application, APIToken, Secret,
    TokenHistory, TokenIPWhitelist
)
from routes.admin_routes import admin_bp
from routes.vault_routes import vault_bp  # make sure vault_bp exists in this file
from routes.api_routes import api_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize SQLAlchemy
    db.init_app(app)

    # Register Blueprints
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(vault_bp, url_prefix='/vault')
    app.register_blueprint(api_bp, url_prefix='/api')

    # Create tables if they don't exist
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    
    #comment the below for production
    #app.run(host='0.0.0.0', port=5000, debug=False) # to run in any interface
    #app.run(debug=True)
