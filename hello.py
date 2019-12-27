# -*- coding=utf-8 -*-
from functools import wraps
from flask import Flask, render_template, session, url_for, redirect, flash, request, abort
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Regexp, equal_to
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, AnonymousUserMixin, current_user

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = '3e9d543c2f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://book_manager:password@localhost/BookManagement'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Permission:
    SEARCH = 0x1
    BORROW = 0x2
    ADMINISTER = 0x80
    ALL_PERPISSION=0xff


class Book(db.Model):
    __tablename__ = 'book'
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    name = db.Column(db.String(64), nullable=False)
    author = db.Column(db.String(64), nullable=False, default='unknown')
    stock = db.Column(db.Integer(), nullable=False, default='0')  # 馆藏量
    price = db.Column(db.Integer(), nullable=False)
    isbn = db.Column(db.String(64), nullable=False)

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

    def __init__(self, **kw):
        super(User, self).__init__()
        if kw.get('admin')==True:
            self.role = Role.query.filter_by(permission=Permission.ALL_PERPISSION).first()
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
        return permission & self.role.permission

    def is_admin(self):
        return self.role.permission & Permission.ADMINISTER


class AnonymousUser(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_admin(self):
        return False


class LendRecord(db.Model):
    __tablename__ = 'lend'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    uid = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    bid = db.Column(db.Integer(), db.ForeignKey('book.id'), nullable=False)
    lend_date_time = db.Column(db.DateTime(), nullable=False)
    return_date_time = db.Column(db.DateTime(), nullable=True)


def reset_db():
    db.drop_all()
    db.create_all()
    db.session.add(Role(id=1, name='admin', permission=Permission.ALL_PERPISSION))
    db.session.add(Role(id=2, name='user', permission=Permission.BORROW | Permission.SEARCH,default=True))
    db.session.commit()


login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)
login_manager.anonymous_user = AnonymousUser


def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def warpper(*args, **kw):
            if not current_user.can(permission):
                abort(403)
            return func(*args,**kw)
        return warpper
    return decorator


def admin_required(func):
    return permission_required(Permission.ADMINISTER)(func)


class NameForm(FlaskForm):
    name = StringField('what your name?', validators=[DataRequired()])
    submit = SubmitField('submit')


class LoginForm(FlaskForm):
    name = StringField('user name', validators=[Regexp('[a-zA-z0-9]{1,64}')])
    password = PasswordField('password', validators=[
                             Regexp('[a-zA-z0-9]{1,64}')])
    remember = BooleanField('remember me')
    log_in = SubmitField('log in')


class registerForm(FlaskForm):
    name = StringField('user name', validators=[Regexp('[a-zA-z0-9]{1,64}')])
    password = PasswordField('password', validators=[
                             Regexp('[a-zA-z0-9]{1,64}', message='password can only contain a-z,A-z,0-9')])
    password2 = PasswordField('password confirm', validators=[
        DataRequired(), equal_to('password', message="passwords don't match")])
    submit = SubmitField('register')

    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('name already exist')


# flask_login需要实现的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        session['name'] = form.name.data
        form.name.data = ''
        if session['name'] == '123':
            flash('aha, my name is 123 too!')
        return redirect(url_for('index'))
    return render_template('index.html', form=form, name=session.get('name'))


@app.route('/user/')
@login_required
def user_page():
    return render_template('user.html', name=current_user.name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None:
            if user.verify_password(form.password.data):
                login_user(user, form.remember.data)
                return redirect(request.args.get('next') or url_for('index'))
            else:
                flash('Invalid user name or password.')
        else:
            flash('user not found.')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('you have been logged out.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', "POST"])
def register():
    form = registerForm()
    if form.validate_on_submit():
        user = User()
        user.name = form.name.data
        user.password = form.password.data
        user.role_id = User.query.filter_by(default=True).first
        db.session.add(user)
        db.session.commit()
        flash('register complete!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/admin')
@login_required
@admin_required
def admin_page():
     return render_template('admin.html')

reset_db()

u = User()
u.name = 'zyf'
u.password = '123'
db.session.add(u)
u2 = User(admin=True)
u2.name = 'admin'
u2.password = '1'
db.session.add(u2)
db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
