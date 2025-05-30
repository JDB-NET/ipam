from flask import Flask
from db import init_db, hash_password
from routes import register_routes
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.config['SECRET_KEY'] = '41TbN7v5peFLZPrdwSCc64J3mjmiUk5fkVWsmb2m'

app.config['MYSQL_HOST'] = '10.10.2.27'
app.config['MYSQL_USER'] = 'ipam'
app.config['MYSQL_PASSWORD'] = 'WXPmo05sGCfjGe'
app.config['MYSQL_DATABASE'] = 'ipam'

register_routes(app)

if __name__ == '__main__':
    with app.app_context():
        init_db(app)
    app.run(host='0.0.0.0', port=5000)