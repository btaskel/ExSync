from flask import Flask

from blueprints.home import bp as home_bp
from blueprints.test import bp as test_bp

app = Flask(__name__)

# 注册蓝图
app.register_blueprint(home_bp)
app.register_blueprint(test_bp)

if __name__ == '__main__':
    app.run(debug=True)
