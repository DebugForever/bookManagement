from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Regexp, equal_to
from ..models import User


class LoginForm(FlaskForm):
    name = StringField('用户名', validators=[Regexp('[a-zA-z0-9]{1,64}')])
    password = PasswordField('密码', validators=[
        Regexp('[a-zA-z0-9]{1,64}')])
    remember = BooleanField('记住我')
    log_in = SubmitField('登录')


class RegisterForm(FlaskForm):
    name = StringField('用户名', validators=[Regexp('[a-zA-z0-9]{1,64}', message='用户名只能包含a-z,A-z,0-9')])
    password = PasswordField('密码', validators=[
        Regexp('[a-zA-z0-9]{1,64}', message='密码只能包含a-z,A-z,0-9')])
    password2 = PasswordField('确认密码', validators=[
        DataRequired(), equal_to('password', message="两次输入密码不一致")])
    submit = SubmitField('注册')

    def validate_name(self, field):
        if User.query.filter_by(name=field.data).first():
            raise ValidationError('用户名已存在')
