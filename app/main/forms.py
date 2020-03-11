from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField
from wtforms.validators import DataRequired


class BookForm(FlaskForm):
    name = StringField('书名', validators=[DataRequired()])
    author = StringField('作者', validators=[DataRequired()])
    stock = IntegerField('馆藏', validators=[DataRequired()])
    price = IntegerField('价格', validators=[DataRequired()])
    isbn = StringField('ISBN', validators=[DataRequired()])
    press = StringField('出版社', validators=[DataRequired()])
    submit = SubmitField('提交')


class BookSearchForm(FlaskForm):
    name = StringField('书名，作者，出版社名，或者ISBN', validators=[DataRequired()])
    submit = SubmitField('搜索')
