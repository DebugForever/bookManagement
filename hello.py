# -*- coding=utf-8 -*-
from functools import wraps
from flask import Flask, render_template, session, url_for, redirect, flash, request, abort
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, IntegerField
from wtforms.validators import DataRequired, Regexp, equal_to
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, AnonymousUserMixin, current_user
from datetime import datetime

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = '3e9d543c2f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://book_manager:password@localhost/BookManagement'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def dangerOperation(func):
    @wraps(func)
    def wrapper(*args, **kw):
        print("you are doing a danger operation, input %s to comfirm." %
              func.__name__)
        if input() != func.__name__:
            print('operation calceled')
            return
        return func(*args, **kw)
    return wrapper


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
        if kw.get('admin') == True:
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


@dangerOperation
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


login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)
login_manager.anonymous_user = AnonymousUser


def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kw):
            if not current_user.can(permission):
                abort(403)
            return func(*args, **kw)
        return wrapper
    return decorator


def admin_required(func):
    return permission_required(Permission.ADMINISTER)(func)


class LoginForm(FlaskForm):
    name = StringField('user name', validators=[Regexp('[a-zA-z0-9]{1,64}')])
    password = PasswordField('password', validators=[
                             Regexp('[a-zA-z0-9]{1,64}')])
    remember = BooleanField('remember me')
    log_in = SubmitField('log in')


class RegisterForm(FlaskForm):
    name = StringField('user name', validators=[Regexp('[a-zA-z0-9]{1,64}')])
    password = PasswordField('password', validators=[
                             Regexp('[a-zA-z0-9]{1,64}', message='password can only contain a-z,A-z,0-9')])
    password2 = PasswordField('password confirm', validators=[
        DataRequired(), equal_to('password', message="passwords don't match")])
    submit = SubmitField('register')

    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('name already exist')


class BookForm(FlaskForm):
    name = StringField('book name', validators=[DataRequired()])
    author = StringField('author', validators=[DataRequired()])
    stock = IntegerField('stock', validators=[DataRequired()])
    price = IntegerField('price', validators=[DataRequired()])
    isbn = StringField('isbn', validators=[DataRequired()])
    press = StringField('press', validators=[DataRequired()])
    submit = SubmitField('submit')


class BookSearchForm(FlaskForm):
    name = StringField('book name', validators=[DataRequired()])
    submit = SubmitField('submit')


# flask_login需要实现的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def index():
    result=None
    if current_user.is_authenticated:
        result = db.session.query(Book,LendRecord)\
            .join(Book,Book.id==LendRecord.bid)\
            .filter(LendRecord.uid == current_user.id, LendRecord.return_date_time == None)\
            .all()
    return render_template('index.html', result=result)


@app.route('/user/')
@login_required
def user_page():
    return render_template('user.html')


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
@login_required
def logout():
    logout_user()
    flash('you have been logged out.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', "POST"])
def register():
    form = RegisterForm()
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


@app.route('/admin/add-book', methods=['GET', 'POST'])
@login_required
@admin_required
def add_book():
    form = BookForm()
    if form.validate_on_submit():
        book = Book()
        book.name = form.name.data
        book.author = form.author.data
        book.stock = form.stock.data
        book.price = form.price.data
        book.isbn = form.isbn.data
        book.press = form.press.data
        db.session.add(book)
        db.session.commit()
        flash('add complete')
        return redirect(url_for('admin_page'))
    return render_template('add-book.html', form=form)


@app.route('/function/search-book', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.SEARCH)
def search_book():
    form = BookSearchForm()
    if form.validate_on_submit():
        name = form.name.data
        result = Book.query.filter(Book.name.like('%'+name+'%')).all()
        return render_template('book-result.html', result=result, name=name)
    return render_template('search-book.html', form=form)


@app.route('/function/show-all-book')
@login_required
def show_all_book():
    result = Book.query.all()
    return render_template('book-result.html', result=result)


@app.route('/function/lend-book', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.BORROW)
def lend_book():
    form = BookSearchForm()
    if form.validate_on_submit():
        name = form.name.data
        book = Book.query.filter_by(name=name).first()
        if book is None:
            flash('book not found')
            return redirect(url_for('lend_book'))
        if book.stock <= 0:
            flash('book not in stock')
            return redirect(url_for('lend_book'))
        record = LendRecord()
        record.bid = book.id
        record.uid = current_user.id
        record.lend_date_time = datetime.now()
        record.return_date_time = None
        book.stock -= 1
        db.session.add(book)
        db.session.add(record)
        db.session.commit()
        flash('successful borrowed %s' % book.name)
        return redirect(url_for('index'))
    return render_template('lend-book.html', form=form)


@app.route('/function/return-book', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.BORROW)
def return_book():
    form = BookSearchForm()
    if form.validate_on_submit():
        name = form.name.data
        book = Book.query.filter_by(name=name).first()
        if book is None:
            flash('book not found')
            return redirect(url_for('return_book'))

        record = LendRecord.query.filter_by(
            bid=book.id, uid=current_user.id, return_date_time=None).first()
        if record is None:
            flash('you had not borrowed this book')
            return redirect(url_for('return_book'))

        record.return_date_time = datetime.now()
        book.stock += 1
        db.session.add(book)
        db.session.add(record)
        db.session.commit()
        flash('successfully returned book')
    return render_template('return_book.html', form=form)

@app.route('/api/return-book')
@login_required
@permission_required(Permission.BORROW)
def return_book_api():
    id=request.args.get('id')
    if id is not None:
        result=LendRecord.query.filter_by(id=id,return_date_time=None)
        count=0
        for row in result:        
            count+=1
            book=Book.query.get(row.bid)
            book.stock+=1
            db.session.add(book)
            row.return_date_time=datetime.now()
            db.session.add(row)
            db.session.commit()
            flash('还书《%s》成功'%book.name)
        if count==0:
            flash('没有找到对应的借书记录')
            return redirect(request.args.get('next') or url_for('index'))
        # flash('还书成功，共还了%d本书'%count)
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/api/lend-book')
@login_required
@permission_required(Permission.BORROW)
def lend_book_api():
    bid=request.args.get('bid')
    if bid is not None:
        book = Book.query.filter_by(id=bid).first()
        if book is None:
            flash('不存在的书')
            return redirect(request.args.get('next') or url_for('index'))
        if book.stock <= 0:
            flash('这本书没有馆藏了')
            return redirect(request.args.get('next') or url_for('index'))
        record = LendRecord()
        record.bid = book.id
        record.uid = current_user.id
        record.lend_date_time = datetime.now()
        record.return_date_time = None
        book.stock -= 1
        db.session.add(book)
        db.session.add(record)
        db.session.commit()
        flash('借书《%s》成功'%book.name)
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/admin/show-all-record')
@login_required
@admin_required
def show_all_record():
    result = LendRecord.query.all()
    return render_template('record-result.html', result=result)


@app.route('/record/u/<user_name>')
@login_required
def show_user_record(user_name):
    user = User.query.filter_by(name=user_name).first()

    if(user.id != current_user.id and not current_user.is_admin()):
        abort(403)
    result = LendRecord.query.filter_by(uid=user.id)
    return render_template('record-result.html', result=result)


@app.route('/admin/show-all-user')
@login_required
@admin_required
def show_all_user():
    result = User.query.all()
    return render_template('user_result.html', result=result)


@app.route('/test')
def test():
    return render_template('test.html')


# reset_db()
if __name__ == '__main__':
    app.run(debug=True)
