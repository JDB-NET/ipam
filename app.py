from flask import Flask
from db import init_db, hash_password
from routes import register_routes
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.config['SECRET_KEY'] = '#{flask-secret}#'

register_routes(app)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)