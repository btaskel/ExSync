import os

from flask import Flask, g

from data.webui.blueprints import home_bp, test_bp
from data.webui.exts import exsync

templates_path = os.path.join('.\\data', 'webui\\templates')
static_path = os.path.join('.\\data', 'webui\\static')

app = Flask(__name__, template_folder=templates_path, static_folder=static_path)

# 初始化EXSync
exsync.init_app(app)


# 创建hook
@app.before_request
def load_exsync_into_g():
    g.exsync = app.extensions['exsync']


# 注册蓝图
app.register_blueprint(home_bp)
app.register_blueprint(test_bp)

if __name__ == '__main__':
    app.run(debug=True)
