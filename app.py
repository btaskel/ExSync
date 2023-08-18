from flask import Flask

from blueprints.home import bp

app = Flask(__name__)

# 注册蓝图
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run(debug=True)
