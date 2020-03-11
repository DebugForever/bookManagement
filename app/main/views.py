from . import main
from datetime import datetime
import re
from sqlalchemy import or_
from flask import render_template, url_for, redirect, flash, request, abort
from flask_login import login_required, current_user
from ..models import LendRecord, Book, User, Permission
from .. import db
from .forms import BookForm, BookSearchForm
from ..decorators import admin_required, permission_required


@main.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if current_user.is_authenticated:
        result = db.session.query(Book, LendRecord) \
            .join(Book, Book.id == LendRecord.bid) \
            .filter(LendRecord.uid == current_user.id, LendRecord.return_date_time is None) \
            .all()
    return render_template('index.html', result=result)


@main.route('/user')
@login_required
def user_page():
    return render_template('user.html')


@main.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html')


@main.route('/admin/add-book', methods=['GET', 'POST'])
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
        flash('添加成功')
        return redirect(url_for('main.admin_page'))
    return render_template('add-book.html', form=form)


@main.route('/function/search-book', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.SEARCH)
def search_book():
    form = BookSearchForm()
    if form.validate_on_submit():
        name = form.name.data
        match_result = re.match(r'[\d-]{13,17}', name)

        name_filter = None
        # ISBN pattern
        if match_result is not None:
            name_filter = Book.isbn == name
        elif name[-3:] == '出版社':
            name_filter = Book.press == name
        else:
            name_filter = or_(Book.name.like('%' + name + '%'), Book.author.like('%' + name + '%'))
        result = Book.query.filter(name_filter).all()
        return render_template('book-result.html', result=result, name=name)
    return render_template('search-book.html', form=form)


@main.route('/function/show-all-book')
@login_required
def show_all_book():
    result = Book.query.all()
    return render_template('book-result.html', result=result)


@main.route('/api/return-book')
@login_required
@permission_required(Permission.BORROW)
def return_book_api():
    id = request.args.get('id')
    if id is not None:
        result = LendRecord.query.filter_by(id=id, return_date_time=None)
        count = 0
        for row in result:
            count += 1
            book = Book.query.get(row.bid)
            book.stock += 1
            db.session.add(book)
            row.return_date_time = datetime.now()
            db.session.add(row)
            db.session.commit()
            flash('还书《%s》成功' % book.name)
        if count == 0:
            flash('没有找到对应的借书记录')
            return redirect(request.args.get('next') or url_for('main.index'))
        # flash('还书成功，共还了%d本书'%count)
    return redirect(request.args.get('next') or url_for('main.index'))


@main.route('/api/lend-book')
@login_required
@permission_required(Permission.BORROW)
def lend_book_api():
    bid = request.args.get('bid')
    if bid is not None:
        book = Book.query.filter_by(id=bid).first()
        if book is None:
            flash('不存在的书')
            return redirect(request.args.get('next') or url_for('main.index'))
        if book.stock <= 0:
            flash('这本书没有馆藏了')
            return redirect(request.args.get('next') or url_for('main.index'))
        record = LendRecord()
        record.bid = book.id
        record.uid = current_user.id
        record.lend_date_time = datetime.now()
        record.return_date_time = None
        book.stock -= 1
        db.session.add(book)
        db.session.add(record)
        db.session.commit()
        flash('借书《%s》成功' % book.name)
    return redirect(request.args.get('next') or url_for('main.index'))


@main.route('/admin/show-all-record')
@login_required
@admin_required
def show_all_record():
    result = LendRecord.query.all()
    return render_template('record-result.html', result=result)


@main.route('/record/u/<user_name>')
@login_required
def show_user_record(user_name):
    user = User.query.filter_by(name=user_name).first()

    if (user.id != current_user.id and not current_user.is_admin()):
        abort(403)
    result = LendRecord.query.filter_by(uid=user.id)
    return render_template('record-result.html', result=result)


@main.route('/admin/show-all-user')
@login_required
@admin_required
def show_all_user():
    result = User.query.all()
    return render_template('user_result.html', result=result)


@main.route('/test')
def test():
    return render_template('test.html')
