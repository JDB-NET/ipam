from flask import Flask
from db import init_db, hash_password
from routes import register_routes
import os
from dotenv import load_dotenv

os.chdir(os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'changeme')

app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'user')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'password')
app.config['MYSQL_DATABASE'] = os.environ.get('MYSQL_DATABASE', 'ipam')

@app.context_processor
def inject_env_vars():
    return {
        'NAME': os.environ.get('NAME', 'JDB-NET'),
        'LOGO_PNG': os.environ.get('LOGO_PNG', 'https://assets.s3.jdbnet.co.uk/logo/128x128.png')
    }

register_routes(app)
init_db(app)