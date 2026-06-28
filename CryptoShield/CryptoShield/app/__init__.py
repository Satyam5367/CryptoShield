from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()
bcrypt = Bcrypt()
jwt = JWTManager()


def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    app.config['SECRET_KEY']              = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
    app.config['JWT_SECRET_KEY']          = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cryptoshield.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
    app.config['MAX_CONTENT_LENGTH']      = 16 * 1024 * 1024  # 16 MB upload limit

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.keys import keys_bp

    app.register_blueprint(auth_bp,   url_prefix='/auth')
    app.register_blueprint(files_bp,  url_prefix='/files')
    app.register_blueprint(keys_bp,   url_prefix='/keys')

    with app.app_context():
        db.create_all()

    return app
