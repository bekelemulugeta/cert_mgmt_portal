import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    VAULT_URL = os.getenv('VAULT_URL')
    VAULT_TOKEN = os.getenv('VAULT_TOKEN')
    VAULT_CACERT=os.getenv('VAULT_CACERT')