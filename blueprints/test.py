import os

from flask import Blueprint, flash, render_template

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

@bp.route('/flash')
def flash_():
    # flash('Test Message')
    return render_template('test.html')