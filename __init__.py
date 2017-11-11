#!/usr/bin/python3

import sqlite3
from flask import Flask, request, render_template, send_from_directory
from flask import session, make_response, abort, redirect, url_for
from flask.ext.session import Session
from werkzeug.utils import secure_filename
import os
import re
from hashlib import sha512, md5
from random import choice
import time
import datetime
import string
import transliterate


app = Flask(__name__)
reg = re.compile('^[A-Za-z0-9]{1,256}$')
templates = {
    'memes': 'memes.html',
    'login': 'login.html',
    'register': 'register.html',
    'new_meme': 'new_meme.html',
}

OR_LVL_MARKS = ("Не оч", "Ну так, норм", "Всей деревней орали", "Ор выше гор")


@app.errorhandler(404)
def four_hundred_four(asd):
    return make_response('<head><style>body {'
                         'background: url("/static/404.jpg")'
                         '}'
                         '</head><body></body>', 404)


def str_chose():
    return ''.join([choice(string.ascii_letters) for _ in range(20)])


@app.route('/')
@app.route('/index.html/')
def re_dir():
    if request.cookies.get('auth'):
        return redirect('/memes/', code=302)
    else:
        return redirect('/login/', code=302)


@app.route('/oauth/', methods=['GET', 'POST'])
def oauth():
    if request.cookies.get('auth'):
        resp = make_response(redirect('/login/'))
        resp.set_cookie('auth', max_age=0)
        return resp
    return redirect('/login/')


@app.route('/register/', methods=['GET', 'POST'])
def register():
    global templates
    global reg
    if request.cookies.get('auth') is not None:
        return redirect('/memes/', code=302)
    if request.method == 'GET':
        return render_template(templates['register'])
    if request.method == 'POST' and request.method == 'POST':
        login = request.form['login']
        password = request.form['pass']
        if password != request.form['confirm_pass']:
            return render_template(templates['register'], error_confirm='Passwords must be equal')
        error_login = []
        error_pass = []
        if not (5 < len(password) < 65):
            error_pass.append("Password must be from 6 to 64 symbols")
        if not re.match(reg, login):
            error_login.append('Login can be only A-Za-z0-9')
        if len(error_pass) or len(error_login):
            return render_template(templates['register'], error_login=error_login, error_pass=error_pass)
        login = login.strip()
        if len(db.execute("SELECT username FROM Users WHERE username='" + login + "'").fetchall()) > 0:
            return render_template(templates['register'], error_login=["This login is occupied"])
        salt = md5(login.encode() + password.encode() + str(len(password)).encode()).hexdigest()
        hashed = md5(str(salt).encode() + password.encode() + str(salt).encode()).hexdigest()
        cookie = sha512(login.encode()).hexdigest() + sha512((str(time.time()) + str_chose()).encode()).hexdigest()
        resp = make_response(redirect('/memes/'))
        resp.set_cookie('auth', cookie, max_age=int(time.time())+31536000)
        db.execute("INSERT INTO Users VALUES ('" + login + "', '" + hashed + "', '" + cookie + "')")
        conn.commit()
        return resp


@app.route('/login/', methods=['GET', 'POST'])
def log_in():
    global reg
    global templates
    if request.cookies.get('auth') is not None:
        return redirect('/memes/', code=302)
    if request.method == 'GET':
        return render_template(templates['login'])
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['pass']
        error_login = []
        error_pass = []
        if not (5 < len(password) < 65):
            error_pass.append("Password must be from 6 to 64 symbols")
        if not re.match(reg, login):
            error_login.append('Login can be only A-Za-z0-9')
        if len(error_pass) or len(error_login):
            return render_template(templates['login'], error_login=error_login, error_pass=error_pass)
        login = login.strip()
        salt = md5(login.encode() + password.encode() + str(len(password)).encode()).hexdigest()
        hashed = md5(str(salt).encode() + password.encode() + str(salt).encode()).hexdigest()
        user = db.execute("SELECT username, pass_hash FROM Users WHERE username='" + login +
                          "' and pass_hash='" + hashed + "'").fetchall()
        if len(user) == 0:
            return render_template(templates['login'], error_login=['Login or password is incorrect'])
        cookie = db.execute("SELECT cookie FROM Users WHERE username=:username", {"username": login}).fetchone()[0]
        resp = make_response(redirect('/memes/'))
        resp.set_cookie('auth', cookie, max_age=int(time.time())+31536000)
        return resp


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/memes/', methods=['GET', 'POST'])
def memeses():
    if request.cookies.get('auth') is None:
        return redirect('/login/', code=302)
    if request.method == 'GET' or request.method == "POST":
        memes = db.execute("SELECT * from Memes").fetchall()
        for i in range(len(memes)):
            memes[i] = list(memes[i])
        for i in range(len(memes)):
            memes[i][4] = OR_LVL_MARKS[memes[i][4]]
        return render_template(templates['memes'], memes=memes[::-1])


@app.route('/new_meme/', methods=['GET', 'POST'])
def new_meme():
    if request.cookies.get('auth') is None:
        return redirect('/login/', code=302)
    if request.method == 'GET':
        return render_template(templates['new_meme'])
    if request.method == 'POST':
        memes_error = []
        file = request.files.get('file')
        if allowed_file(file.filename) or file.filename == '':
            filename = secure_filename(transliterate.translit(file.filename, 'ru', reversed=True))
            if filename:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            username = db.execute("SELECT username FROM Users WHERE cookie=:cookie",
                                  {"cookie": request.cookies.get('auth')}).fetchone()[0]
            dt = str(datetime.datetime.fromtimestamp(time.time()+10080)).split('.')[0]
            text = request.form['text']
            or_lvl = str(request.form['or_lvl'])
            if not (text or filename):
                memes_error.append('Зачем ты кидаешь пустой мемес? а? а?')
            if not or_lvl:
                memes_error.append('Поставь мему оценку, пж')
            if memes_error:
                return render_template(templates['new_meme'], memes_error=memes_error)
            db.execute("INSERT INTO Memes VALUES (:username, :datetime, :text, :img_src, :or_lvl)",
                       {"username": username, "datetime": dt, "img_src": filename, "text": text, "or_lvl": or_lvl})
            conn.commit()
            return redirect('/memes/')
        else:
            memes_error.append('Ты имеешь наглость кидать не картинки?')
        return render_template(templates['new_meme'], memes_error=memes_error)


@app.route('/uploads/<path:filename>/', methods=['GET', 'POST'])
def get_meme(filename):
    print(filename)
    return send_from_directory(directory=app.config['UPLOAD_FOLDER'], filename=filename)


if __name__ == "__main__":
    conn = sqlite3.connect('Raneddo_memes.db')
    db = conn.cursor()
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.run(port='7828')
