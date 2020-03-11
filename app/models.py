from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
from . import login_manager


class Permission:
    SEARCH = 0x1
    BORROW = 0x2
    RESERVED1 = 0x4
    RESERVED2 = 0x8
    RESERVED3 = 0x10
    RESERVED4 = 0x20
    RESERVED5 = 0x40
    ADMINISTER = 0x80
    ALL_PERPISSION = 0xff


class Book(db.Model):
    __tablename__ = 'book'
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    name = db.Column(db.String(64), nullable=False)
    author = db.Column(db.String(64), nullable=False, default='unknown')
    stock = db.Column(db.Integer(), nullable=False, default='0')  # 馆藏量
    price = db.Column(db.Integer(), nullable=False)
    isbn = db.Column(db.String(64), nullable=False)
    press = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return '<book %r>' % self.name


class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    name = db.Column(db.String(64), nullable=False)
    permission = db.Column(db.Integer(), nullable=False)
    default = db.Column(db.Boolean(), default=False)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id'))
    default = db.Column(db.Boolean(), nullable=False, default=False)

    def __init__(self, **kw):
        super(User, self).__init__()
        if kw.get('admin'):
            self.role = Role.query.filter_by(
                permission=Permission.ALL_PERPISSION).first()
        elif self.role is None:
            self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def verify_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    def __repr__(self):
        return '<user %r>' % self.name

    def can(self, permission):
        return bool(permission & self.role.permission)

    def is_admin(self):
        return bool(self.role.permission & Permission.ADMINISTER)


class AnonymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_admin(self):
        return False


class LendRecord(db.Model):
    __tablename__ = 'lend'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    uid = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='record')
    bid = db.Column(db.Integer(), db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book', backref='record')
    lend_date_time = db.Column(db.DateTime(), nullable=False)
    return_date_time = db.Column(db.DateTime(), nullable=True)


def reset_db():
    db.drop_all()
    db.create_all()
    db.session.add(
        Role(id=1, name='admin', permission=Permission.ALL_PERPISSION))
    db.session.add(Role(id=2, name='user',
                        permission=Permission.BORROW | Permission.SEARCH, default=True))
    db.session.commit()

    u = User()
    u.name = 'test'
    u.password = '123'
    db.session.add(u)
    u2 = User(admin=True)
    u2.name = 'admin'
    u2.password = '1'
    db.session.add(u2)
    db.session.commit()


# flask_login需要实现的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


login_manager.anonymous_user = AnonymousUser
