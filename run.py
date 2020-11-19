from __future__ import print_function
from flask import Flask, request, render_template, redirect, url_for, session, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.sql import func
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from functools import wraps
import requests
import base64


app = Flask(__name__)
Bootstrap(app)
app.config.from_mapping(SECRET_KEY='xrid6*9Kd@I5')


# TODO: change localhost to db after testing
dbURL = 'mysql+mysqlconnector://root@localhost:3306/access'
app.config['SQLALCHEMY_DATABASE_URI'] = dbURL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'users'

    fin = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.Integer, nullable=False)
    allowentry = db.Column(db.Boolean, nullable=False)
    allowexit = db.Column(db.Boolean, nullable=False)

    def __init__(self, fin, name, phone, allowentry, allowexit):
        self.fin = fin
        self.name = name
        self.phone = phone
        self.allowentry = allowentry
        self.allowexit = allowexit


class Log(db.Model):
    __tablename__ = 'log'

    logid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime(timezone=True),
                          server_default=func.now())
    activity = db.Column(db.String(20), nullable=False)
    fin = db.Column(db.String(20), nullable=False)
    safeentry = db.Column(db.String(50), nullable=True)

    def __init__(self, logid, timestamp, activity, fin, safeentry):
        self.logid = logid
        self.timestamp = timestamp
        self.activity = activity
        self.fin = fin
        self.safeentry = safeentry


engine = create_engine(dbURL)
if not database_exists(engine.url):
    create_database(engine.url)
db.create_all()
db.session.commit()


class MainForm(FlaskForm):
    barcode = StringField(
        'Scan Barcode', [DataRequired()], render_kw={'autofocus': True})


SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
SPREADSHEET_ID = '1VAlrUlYjjr2XJ16gpLU8s-ubno7-XqkMxWpVqsKhMVU'
RANGE_NAME = 'Sheet1!A2:E'


def adminonly(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        if session['username'] != 'admin':
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def terminalonly(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        if session['username'] != 'terminal':
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    elif session['username'] == 'terminal':
        return redirect(url_for('terminal'))
    elif session['username'] == 'admin':
        return redirect(url_for('admin'))


@app.route('/terminal', methods=('GET', 'POST'))
@terminalonly
def terminal():
    form = MainForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        barcode = form.barcode.data
        fin = barcode[:9]
        form.barcode.data = None
        lastlog = Log.query.filter_by(fin=fin).order_by(
            Log.logid.desc()).first()
        if lastlog:
            lastactivity = lastlog.activity
            if lastactivity == 'ENTRY':
                activity = "EXIT"
            else:
                activity = 'ENTRY'
        else:
            activity = 'ENTRY'
        user = Users.query.filter_by(fin=fin).first()
        if activity == 'ENTRY':
            if user:
                allowed = bool(user.allowentry)
            else:
                allowed = False
            if not allowed:
                return render_template('access.html', form=form, boxtype='errorbox', boxtext='Not Permitted to Enter')
            else:
                fin = user.fin
                name = user.name
                safeentry = checkin(fin)
                logdata = {'logid': None, 'timestamp': None,
                           'activity': activity, 'fin': fin, 'safeentry': safeentry}
                logitem = Log(**logdata)
                db.session.add(logitem)
                db.session.commit()
                if safeentry:
                    location = requests.get(
                        "https://backend.safeentry-qr.gov.sg/api/v2/transaction/{}".format(safeentry)).json()['message']['venueName']
                    return render_template('access.html', form=form, boxtype='successbox', boxtext='CHECK IN:', name=name, location=location)
                else:
                    return render_template('access.html', form=form, boxtype='warnbox', boxtext='CHECK IN (do manual SafeEntry):', name=name)
        elif activity == "EXIT":
            if user:
                allowed = bool(user.allowexit)
            else:
                allowed = False
            if not allowed:
                return render_template('access.html', form=form, boxtype='errorbox', boxtext='Not Permitted to Exit')
            else:
                fin = user.fin
                name = user.name
                safeentry = checkout(fin)
                logdata = {'logid': None, 'timestamp': None,
                           'activity': activity, 'fin': fin, 'safeentry': safeentry}
                logitem = Log(**logdata)
                db.session.add(logitem)
                db.session.commit()
                if safeentry:
                    location = requests.get(
                        "https://backend.safeentry-qr.gov.sg/api/v2/transaction/{}".format(safeentry)).json()['message']['venueName']
                    return render_template('access.html', form=form, boxtype='successbox', boxtext='CHECK OUT:', name=name, location=location)
                else:
                    return render_template('access.html', form=form, boxtype='warnbox', boxtext='CHECK OUT (do manual SafeEntry):', name=name)
    return render_template('access.html', form=form, boxtype=None)


@app.route('/admin')
@adminonly
def admin():
    return render_template('admin.html')


@app.route('/status')
@adminonly
def status():
    users = Users.query.all()
    userdict = {}
    for user in users:
        fin = user.fin
        lastlog = Log.query.filter_by(fin=fin).order_by(
            Log.logid.desc()).first()
        if lastlog:
            lastactivity = lastlog.activity
            if lastactivity == 'ENTRY':
                status = 'IN'
            else:
                status = 'OUT'
        else:
            status = 'OUT'
        userdict[user] = status
    return render_template('status.html', userdict=userdict)


@app.route('/log', methods=['POST'])
@adminonly
def log():
    fin = request.form['fin']
    userlog = Log.query.filter_by(fin=fin).order_by(Log.logid.desc()).all()
    return render_template('log.html', userlog=userlog, fin=fin)


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = MainForm(request.form)
    if request.method == 'POST' and form.validate_on_submit():
        logindata = form.barcode.data
        if logindata == 'terminal#test':
            session['username'] = 'terminal'
            return redirect(url_for('home'))
        elif logindata == 'admin#test':
            session['username'] = 'admin'
            return redirect(url_for('home'))
        else:
            abort(403)
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username', None)
    return redirect(url_for('home'))


@app.route('/gsheetsync')
@adminonly
def gsheetsync():
    try:
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        service = build('sheets', 'v4', credentials=creds)

        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=RANGE_NAME).execute()
        values = result.get('values', [])
    except:
        return "ERROR: Unable to retrieve Google Sheet"

    for row in values:
        try:
            fin = row[0]
            name = row[1]
            phone = row[2]
            allowentry = bool(row[3])
            allowexit = bool(row[4])
        except:
            return "ERROR: Invalid data in Google Sheet"
        try:
            data = {"fin": fin, "name": name, "phone": phone,
                    "allowentry": allowentry, "allowexit": allowexit}
            user = Users(**data)
            db.session.merge(user)
            db.session.commit()
        except:
            return "ERROR: Database update failed"

    return "SUCCESS"


def checkin(fin):
    client_id = 'PROD-200200876R-141617-ADDWALLETREKHQ-SE'
    phone = Users.query.filter_by(fin=fin).first().phone
    mobileno = base64.b64encode(str(phone).encode('ascii'))
    payload = {'mobileno': mobileno, 'client_id': client_id, 'subentity': 1, 'hostname': None, 'systemType': 'safeentry',
               'mobilenoEncoded': True, 'sub': fin, 'actionType': 'checkin', 'subType': 'uinfin', 'rememberMe': False}
    r = requests.post(
        "https://backend.safeentry-qr.gov.sg/api/v2/person", data=payload)
    try:
        return r.json()['message']['transactionId']
    except:
        return None


def checkout(fin):
    transactionId = Log.query.filter_by(fin=fin).order_by(
        Log.logid.desc()).first().safeentry
    if not transactionId:
        return None
    r = requests.post(
        "https://backend.safeentry-qr.gov.sg/api/v2/transaction/{}".format(transactionId))
    try:
        return r.json()['message']['transactionId']
    except:
        return None


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, threaded=True, debug=True)
