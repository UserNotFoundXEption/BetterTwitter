from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, UserMixin
from flask_cors import CORS

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['USER_ENABLE_EMAIL'] = False
    app.config['USER_APP_NAME'] = "Flask App"

    db.init_app(app)
    CORS(app)

    from app.models import User
    from app.routes import setup_routes

    user_manager = UserManager(app, db, User)
    setup_routes(app)

    return app

