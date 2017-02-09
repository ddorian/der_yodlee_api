# coding=utf-8
from flask_script import Manager
from app import app, db

manager = Manager(app)


def sub_opts(app, **kwargs):
    return


from flask_migrate import Migrate, MigrateCommand

migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

@manager.command
def run_debug():
    # configure main flask logger only on uwsgi stderr
    app.debug = True
    app.run(port=5000)


@manager.command
def create_tables():
    db.create_all()


@manager.command
def drop_tables():
    db.drop_all()


if __name__ == '__main__':
    manager.run()
