from .forms import LoginForm, RegisterForm
from ..models import User
from .. import db
from flask import flash, redirect, request, url_for, render_template
from flask_login import login_user, logout_user, login_required
from . import auth


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(name=form.name.data).first()
        if user is not None:
            if user.verify_password(form.password.data):
                login_user(user, form.remember.data)
                return redirect(request.args.get('next') or url_for('main.index'))
            else:
                flash('用户名与密码不匹配')
        else:
            flash('用户未找到')
    return render_template('login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User()
        user.name = form.name.data
        user.password = form.password.data
        user.role_id = User.query.filter_by(default=True).first
        db.session.add(user)
        db.session.commit()
        flash('注册成功！')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)
