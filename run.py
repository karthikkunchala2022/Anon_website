from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import datetime
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Liquidmind.AI!@#$%^&*'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/liquidmind'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class MSME(db.Model):
    __tablename__ = 'MSME'
    id = db.Column('MSME_ID', db.String(64), primary_key=True)
    email = db.Column('MSME_EMAIL', db.String(120), unique=True, nullable=False)
    password = db.Column('MSME_PASSWORD', db.String(128), nullable=False)
    erp = db.Column('MSME_ERP', db.String(50), nullable=False)
    erp_id = db.Column('MSME_ERP_ID', db.String(50), nullable=False)
    phone_number = db.Column('MSME_PHONE_NUMBER', db.String(20), nullable=False)

def generate_msme_id(email):
    now = datetime.datetime.now()
    datetime_str = now.strftime('%Y%m%d%H%M%S%f')
    unique_str = email + datetime_str
    user_id = hashlib.sha256(unique_str.encode()).hexdigest()
    return user_id

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    erp = request.form['erp']
    erp_id = request.form['erp_id']
    phone_number = request.form['phone_number']

    # Check if passwords match
    if password != confirm_password:
        flash('Passwords do not match!')
        return redirect(url_for('index'))

    # Check if email already exists
    existing_msme = MSME.query.filter_by(email=email).first()
    if existing_msme:
        flash('Email already exists!')
        return redirect(url_for('index'))

    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Generate MSME ID
    msme_id = generate_msme_id(email)

    # Create new MSME instance
    new_user = MSME(
        id=msme_id,
        email=email,
        password=hashed_password,
        erp=erp,
        erp_id=erp_id,
        phone_number=phone_number
    )

    # Add to database
    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful!')
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    # Find MSME by email
    msme = MSME.query.filter_by(email=email).first()

    if not msme or not bcrypt.check_password_hash(msme.password, password):
        flash('Login Unsuccessful. Please check email and password.')
        return redirect(url_for('index'))

    flash('Login successful!')
    return redirect(url_for('index'))

@app.route('/google_login')
def google_login():
    # Implement Google OAuth login
    pass

if __name__ == '__main__':
    app.run(debug=True)
