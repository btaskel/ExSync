import os

from flask import Blueprint

from server.sync import SyncData

bp = Blueprint('test', __name__, url_prefix='/test')


@bp.route('/')
def test():
    print(os.getcwd())
    p = '.\\test\\space'
    s = SyncData(p)
    # s.updateIndex(p)
    s.initIndex()
    s.createIndex()

    return 'ok'
