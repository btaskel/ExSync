import os

from flask import Flask

from data.blueprints import home_bp, test_bp

templates_path = os.path.join('.\\data', 'templates')
static_path = os.path.join('.\\data', 'static')

app = Flask(__name__, template_folder=templates_path, static_folder=static_path)

# 注册蓝图
app.register_blueprint(home_bp)
app.register_blueprint(test_bp)

if __name__ == '__main__':
    app.run(debug=True)
