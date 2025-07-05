# app.py
# This is the main application file for the Gym Tracker platform.

import os
import io
import secrets
import calendar
import random
import string
import base64
from functools import wraps
from datetime import datetime, date, timedelta

from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_file, session, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_babel import Babel, _
from sqlalchemy import func
from PIL import Image
import pandas as pd
from wtforms import validators
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
import pyotp
import qrcode

from modeldb import db, User, Attendance, BodyMeasurement
from forms import (LoginForm, UserForm, ChangePasswordForm, 
                   RequestResetForm, ResetPasswordForm, UpdateAccountForm, BodyMeasurementForm, OTPForm)

# --- App Configuration ---
app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.i18n')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-and-secure-key-for-development')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)
db_path = os.path.join(instance_path, 'gym_tracker.db')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Babel Configuration ---
app.config['LANGUAGES'] = ['en', 'es']
def get_locale():
    return session.get('language', 'en')

babel = Babel(app, locale_selector=get_locale)

# --- Initialize Extensions ---
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = _('Please log in to access this page.')

# Decorators and User Loader
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role_name:
                flash(_("You do not have permission to access this page."), "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_or_trainer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'trainer']:
            flash(_("You do not have permission to access this page."), "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    profile_pics_path = os.path.join(app.root_path, 'static/profile_pics')
    os.makedirs(profile_pics_path, exist_ok=True)
    picture_path = os.path.join(profile_pics_path, picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

def get_calendar_data(user_id, year, month):
    cal = calendar.Calendar()
    month_days = cal.itermonthdates(year, month)
    start_of_month = date(year, month, 1)
    end_of_month = date(year, month, calendar.monthrange(year, month)[1])
    attendance_records = Attendance.query.filter(Attendance.user_id == user_id, Attendance.check_in_timestamp >= start_of_month, Attendance.check_in_timestamp <= end_of_month).all()
    attended_dates = {record.check_in_timestamp.date() for record in attendance_records}
    calendar_days = []
    today = date.today()
    for day in month_days:
        if day.month == month:
            calendar_days.append({"number": day.day, "date_str": day.isoformat(), "attended": day in attended_dates, "is_today": day == today, "is_future": day > today})
        else:
            calendar_days.append({"number": 0, "date_str": None, "attended": False, "is_today": False, "is_future": False})
    return calendar_days

def generate_random_password(length=4):
    characters = string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Main Routes
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)
    session.modified = True
    g.locale = str(get_locale())

@app.route('/')
def index():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/language/<language>')
def set_language(language=None):
    session['language'] = language
    return redirect(request.referrer)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.is_active:
                if user.is_otp_enabled:
                    session['otp_user_id'] = user.id
                    return redirect(url_for('verify_otp'))
                
                login_user(user)
                session.permanent = True
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else: flash(_('This account is inactive. Please contact an administrator.'), 'error')
        else: flash(_('Invalid username or password.'), 'error')
    return render_template('login.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_user_id' not in session:
        return redirect(url_for('login'))
    
    form = OTPForm()
    if form.validate_on_submit():
        user_id = session['otp_user_id']
        user = User.query.get(user_id)
        if user and user.verify_totp(form.token.data):
            session.pop('otp_user_id', None)
            login_user(user)
            session.permanent = True
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash(_('Invalid authentication code.'), 'error')
    return render_template('otp_verify.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin': return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'member': return redirect(url_for('member_dashboard'))
    elif current_user.role == 'trainer': return redirect(url_for('trainer_dashboard'))
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(_('You have been logged out.'))
    return redirect(url_for('login'))

# Account Management Routes
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            current_user.image_file = save_picture(form.picture.data)
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.full_name = form.full_name.data
        db.session.commit()
        flash(_('Your account has been updated!'), 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.full_name.data = current_user.full_name
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', form=form, image_file=image_file)

@app.route('/otp_setup', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def otp_setup():
    form = OTPForm()
    if form.validate_on_submit():
        if current_user.verify_totp(form.token.data):
            current_user.is_otp_enabled = True
            db.session.commit()
            flash(_('Two-Factor Authentication has been enabled!'), 'success')
            return redirect(url_for('account'))
        else:
            flash(_('Invalid verification code. Please try again.'), 'error')
    
    qr_code_uri = current_user.get_totp_uri()
    img = qrcode.make(qr_code_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    qr_code_image = base64.b64encode(buf.getvalue()).decode('ascii')
    
    return render_template('otp_setup.html', qr_code_image=qr_code_image, form=form)

@app.route('/disable_otp', methods=['POST'])
@login_required
@role_required('admin')
def disable_otp():
    current_user.is_otp_enabled = False
    db.session.commit()
    flash(_('Two-Factor Authentication has been disabled.'), 'success')
    return redirect(url_for('account'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash(_('Your password has been updated successfully!'), 'success')
            return redirect(url_for('dashboard'))
        else: flash(_('Incorrect old password.'), 'error')
    return render_template('change_password.html', form=form)

def get_reset_token(user):
    s = Serializer(app.config['SECRET_KEY'])
    return s.dumps({'user_id': user.id})

def verify_reset_token(token, expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'])
    try: user_id = s.loads(token, max_age=expires_sec)['user_id']
    except: return None
    return User.query.get(user_id)

@app.route('/reset_password', methods=['GET', 'POST'])
def request_reset():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = get_reset_token(user)
            reset_link = url_for('reset_token', token=token, _external=True)
            print(f"--- PASSWORD RESET LINK for {user.email} ---\n{reset_link}\n-------------------------------------------------------------")
            flash(_('A password reset link has been generated. For now, check the server console.'), 'info')
        else: flash(_('No account found with that email address.'), 'warning')
    return render_template('request_reset.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    user = verify_reset_token(token)
    if user is None:
        flash(_('That is an invalid or expired token.'), 'warning')
        return redirect(url_for('request_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been updated! You are now able to log in.'), 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Member Routes
@app.route('/member/dashboard')
@login_required
@role_required('member')
def member_dashboard():
    today = datetime.utcnow().date()
    start_of_month = today.replace(day=1)
    visits_this_month = Attendance.query.filter(Attendance.user_id == current_user.id, func.date(Attendance.check_in_timestamp) >= start_of_month).count()
    trainer_name = current_user.trainer.full_name if current_user.trainer else None
    calendar_title = today.strftime("%B %Y")
    calendar_days = get_calendar_data(current_user.id, today.year, today.month)
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('member_dashboard.html', image_file=image_file, visits_this_month=visits_this_month, trainer_name=trainer_name, calendar_title=calendar_title, calendar_days=calendar_days)

@app.route('/update_measurements', methods=['GET', 'POST'])
@login_required
@role_required('member')
def update_measurements():
    form = BodyMeasurementForm()
    if form.validate_on_submit():
        measurement = BodyMeasurement(
            user_id=current_user.id,
            weight_kg=form.weight_kg.data,
            height_cm=form.height_cm.data,
            body_fat_percentage=form.body_fat_percentage.data,
            muscle_mass_kg=form.muscle_mass_kg.data,
            bone_mass_kg=form.bone_mass_kg.data,
            visceral_fat_rating=form.visceral_fat_rating.data
        )
        db.session.add(measurement)
        db.session.commit()
        flash(_('Your new measurements have been saved!'), 'success')
        return redirect(url_for('member_dashboard'))
    return render_template('update_measurements.html', form=form)

# Trainer & Admin Shared Routes
@app.route('/member_profile/<int:member_id>')
@login_required
@admin_or_trainer_required
def member_profile(member_id):
    member = User.query.get_or_404(member_id)
    if current_user.role == 'trainer' and member not in current_user.assigned_members:
        flash(_('You do not have permission to view this profile.'), 'error')
        return redirect(url_for('trainer_dashboard'))
    
    measurements = BodyMeasurement.query.filter_by(user_id=member.id).order_by(BodyMeasurement.report_date.desc()).all()
    
    chart_data = {
        'labels': [m.report_date.strftime('%b %d') for m in measurements],
        'data': [m.weight_kg for m in measurements]
    }
    
    return render_template('member_profile.html', member=member, measurements=measurements, chart_data=chart_data)

@app.route('/add_measurement/<int:member_id>', methods=['GET', 'POST'])
@login_required
@admin_or_trainer_required
def add_measurement(member_id):
    member = User.query.get_or_404(member_id)
    if current_user.role == 'trainer' and member not in current_user.assigned_members:
        flash(_('You do not have permission to add measurements for this member.'), 'error')
        return redirect(url_for('trainer_dashboard'))
    
    form = BodyMeasurementForm()
    if form.validate_on_submit():
        measurement = BodyMeasurement(
            user_id=member.id,
            weight_kg=form.weight_kg.data,
            height_cm=form.height_cm.data,
            body_fat_percentage=form.body_fat_percentage.data,
            muscle_mass_kg=form.muscle_mass_kg.data,
            bone_mass_kg=form.bone_mass_kg.data,
            visceral_fat_rating=form.visceral_fat_rating.data
        )
        db.session.add(measurement)
        db.session.commit()
        flash(_('New measurements for %(member_name)s have been saved!', member_name=member.full_name), 'success')
        return redirect(url_for('member_profile', member_id=member.id))
    
    return render_template('update_measurements.html', form=form, member=member)

@app.route('/mark_attendance/<int:member_id>', methods=['GET'])
@login_required
@admin_or_trainer_required
def mark_attendance(member_id):
    member = User.query.get_or_404(member_id)
    if member.role != 'member':
        flash(_('You can only mark attendance for members.'), 'error')
        return redirect(url_for('dashboard'))
    if current_user.role == 'trainer' and member not in current_user.assigned_members:
        flash(_('You do not have permission to mark attendance for this member.'), 'error')
        return redirect(url_for('trainer_dashboard'))
    year = request.args.get('year', default=date.today().year, type=int)
    month = request.args.get('month', default=date.today().month, type=int)
    current_date = date(year, month, 1)
    calendar_title = current_date.strftime("%B %Y")
    calendar_days = get_calendar_data(member.id, year, month)
    prev_month_date = current_date - timedelta(days=1)
    prev_month = {'year': prev_month_date.year, 'month': prev_month_date.month}
    next_month_date = (current_date + timedelta(days=31)).replace(day=1)
    next_month = {'year': next_month_date.year, 'month': next_month_date.month}
    return render_template('mark_attendance.html', member=member, calendar_days=calendar_days, calendar_title=calendar_title, prev_month=prev_month, next_month=next_month)

@app.route('/toggle_attendance/<int:member_id>/<date_str>')
@login_required
@admin_or_trainer_required
def toggle_attendance(member_id, date_str):
    member = User.query.get_or_404(member_id)
    attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    if current_user.role == 'trainer' and member not in current_user.assigned_members:
        flash(_('You do not have permission to modify attendance for this member.'), 'error')
        return redirect(url_for('trainer_dashboard'))
    existing_record = Attendance.query.filter(Attendance.user_id == member.id, func.date(Attendance.check_in_timestamp) == attendance_date).first()
    if existing_record:
        db.session.delete(existing_record)
        flash(_('Attendance removed for %(member_name)s on %(date)s.', member_name=member.full_name, date=date_str), 'success')
    else:
        new_attendance = Attendance(user_id=member.id, check_in_timestamp=datetime.combine(attendance_date, datetime.min.time()))
        db.session.add(new_attendance)
        flash(_('Attendance marked for %(member_name)s on %(date)s.', member_name=member.full_name, date=date_str), 'success')
    db.session.commit()
    return redirect(url_for('mark_attendance', member_id=member_id, year=attendance_date.year, month=attendance_date.month))

# Trainer Routes
@app.route('/trainer/dashboard')
@login_required
@role_required('trainer')
def trainer_dashboard():
    clients = current_user.assigned_members.filter_by(is_active=True).all()
    today = datetime.utcnow().date()
    start_of_month = today.replace(day=1)
    for client in clients:
        last_check_in_record = Attendance.query.filter_by(user_id=client.id).order_by(Attendance.check_in_timestamp.desc()).first()
        client.last_check_in = last_check_in_record.check_in_timestamp if last_check_in_record else None
        client.visits_this_month = Attendance.query.filter(Attendance.user_id == client.id, func.date(Attendance.check_in_timestamp) >= start_of_month).count()
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('trainer_dashboard.html', clients=clients, image_file=image_file)

@app.route('/trainer/edit_client/<int:client_id>', methods=['GET', 'POST'])
@login_required
@role_required('trainer')
def edit_client(client_id):
    client = User.query.get_or_404(client_id)
    if client not in current_user.assigned_members:
        flash(_('You do not have permission to edit this client.'), 'error')
        return redirect(url_for('trainer_dashboard'))
    
    form = UserForm(obj=client)
    trainers = User.query.filter_by(role='trainer').all()
    form.trainer_id.choices = [(t.id, t.full_name) for t in trainers]
    form.trainer_id.choices.insert(0, (0, 'None'))

    if form.validate_on_submit():
        client.full_name = form.full_name.data
        client.date_of_birth = form.date_of_birth.data
        client.gender = form.gender.data
        client.injuries = form.injuries.data
        client.objective = form.objective.data
        client.intensity = form.intensity.data
        if form.picture.data:
            client.image_file = save_picture(form.picture.data)
        db.session.commit()
        flash(_('Client %(user_name)s updated successfully.', user_name=client.full_name), 'success')
        return redirect(url_for('trainer_dashboard'))

    image_file = url_for('static', filename='profile_pics/' + client.image_file)
    return render_template('user_form.html', form=form, title=_("Edit Client Profile"), image_file=image_file)


# Admin Routes
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    members = User.query.filter_by(role='member').order_by(User.full_name).all()
    trainers = User.query.filter_by(role='trainer').order_by(User.full_name).all()
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('admin_dashboard.html', members=members, trainers=trainers, image_file=image_file)

@app.route('/admin/user/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    form = UserForm()
    trainers = User.query.filter_by(role='trainer').all()
    form.trainer_id.choices = [(t.id, t.full_name) for t in trainers]
    form.trainer_id.choices.insert(0, (0, 'None'))
    
    form.password.validators = []
    form.confirm_password.validators = []
    
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash(_('Username already exists.'), 'error')
            return render_template('user_form.html', form=form, title=_("Add New User"))
        if User.query.filter_by(email=form.email.data).first():
            flash(_('Email address already exists.'), 'error')
            return render_template('user_form.html', form=form, title=_("Add New User"))
        
        temp_password = generate_random_password()
        
        new_user = User(
            username=form.username.data, email=form.email.data, full_name=form.full_name.data,
            role=form.role.data, is_active=form.is_active.data,
            date_of_birth=form.date_of_birth.data, gender=form.gender.data,
            injuries=form.injuries.data, objective=form.objective.data, intensity=form.intensity.data
        )
        new_user.set_password(temp_password)
        if form.picture.data:
            new_user.image_file = save_picture(form.picture.data)
        if new_user.role == 'member' and form.trainer_id.data != 0:
            new_user.trainer_id = form.trainer_id.data
        db.session.add(new_user)
        db.session.commit()
        flash(_('User %(user_name)s created successfully. Their temporary password is: %(password)s', user_name=new_user.full_name, password=temp_password), 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('user_form.html', form=form, title=_("Add New User"))

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    form = UserForm(obj=user_to_edit)
    trainers = User.query.filter_by(role='trainer').all()
    form.trainer_id.choices = [(t.id, t.full_name) for t in trainers]
    form.trainer_id.choices.insert(0, (0, 'None'))
    if form.validate_on_submit():
        user_to_edit.username = form.username.data
        user_to_edit.email = form.email.data
        user_to_edit.full_name = form.full_name.data
        user_to_edit.role = form.role.data
        user_to_edit.is_active = form.is_active.data
        user_to_edit.date_of_birth = form.date_of_birth.data
        user_to_edit.gender = form.gender.data
        user_to_edit.injuries = form.injuries.data
        user_to_edit.objective = form.objective.data
        user_to_edit.intensity = form.intensity.data
        if form.picture.data:
            user_to_edit.image_file = save_picture(form.picture.data)
        if form.password.data:
            user_to_edit.set_password(form.password.data)
        if user_to_edit.role == 'member':
            user_to_edit.trainer_id = form.trainer_id.data if form.trainer_id.data != 0 else None
        else: user_to_edit.trainer_id = None
        db.session.commit()
        flash(_('User %(user_name)s updated successfully.', user_name=user_to_edit.full_name), 'success')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'GET':
        form.trainer_id.data = user_to_edit.trainer_id or 0
        form.is_active.data = user_to_edit.is_active
    image_file = url_for('static', filename='profile_pics/' + user_to_edit.image_file)
    return render_template('user_form.html', form=form, title=_("Edit %(user_name)s", user_name=user_to_edit.full_name), image_file=image_file)

# Excel Report and CLI Commands
@app.route('/admin/report/excel/<int:member_id>')
@login_required
@admin_or_trainer_required
def download_excel_report(member_id):
    member = User.query.get_or_404(member_id)
    attendance_query = db.session.query(func.date(Attendance.check_in_timestamp).label('date'), func.strftime('%Y-%m', Attendance.check_in_timestamp).label('month')).filter(Attendance.user_id == member.id).all()
    attendance_df = pd.DataFrame(attendance_query, columns=['Date', 'Month'])
    summary_df = pd.DataFrame(columns=['Month', 'Total Visits'])
    if not attendance_df.empty:
        summary_df = attendance_df.groupby('Month').count().reset_index()
        summary_df.columns = ['Month', 'Total Visits']
    measurement_query = db.session.query(BodyMeasurement.report_date, BodyMeasurement.weight_kg, BodyMeasurement.height_cm, BodyMeasurement.body_fat_percentage, BodyMeasurement.muscle_mass_kg).filter(BodyMeasurement.user_id == member.id).order_by(BodyMeasurement.report_date.asc()).all()
    measurements_df = pd.DataFrame(measurement_query, columns=['Date', 'Weight (kg)', 'Height (cm)', 'Body Fat %', 'Muscle Mass (kg)'])
    if not measurements_df.empty:
        measurements_df['BMI'] = round(measurements_df['Weight (kg)'] / ((measurements_df['Height (cm)'] / 100) ** 2), 1)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        summary_df.to_excel(writer, sheet_name='Attendance Summary', index=False)
        attendance_df.to_excel(writer, sheet_name='Attendance Log', index=False)
        measurements_df.to_excel(writer, sheet_name='Measurement History', index=False)
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'{member.username}_Report.xlsx')

@app.route('/admin/report/general_excel')
@login_required
@role_required('admin')
def download_general_report():
    members = User.query.filter_by(role='member', is_active=True).all()
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        for member in members:
            sheet_name = member.username[:31]
            measurement_query = db.session.query(BodyMeasurement.report_date, BodyMeasurement.weight_kg, BodyMeasurement.height_cm, BodyMeasurement.body_fat_percentage).filter(BodyMeasurement.user_id == member.id).order_by(BodyMeasurement.report_date.asc()).all()
            measurements_df = pd.DataFrame(measurement_query, columns=['Date', 'Weight (kg)', 'Height (cm)', 'Body Fat %'])
            if not measurements_df.empty:
                measurements_df['BMI'] = round(measurements_df['Weight (kg)'] / ((measurements_df['Height (cm)'] / 100) ** 2), 1)
            measurements_df.to_excel(writer, sheet_name=sheet_name, index=False, startrow=1)
            worksheet = writer.sheets[sheet_name]
            worksheet.write(0, 0, f"Progress Report for {member.full_name}")
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'General_Member_Report_{date.today().isoformat()}.xlsx')

@app.cli.command("create-admin")
def create_admin_command():
    with app.app_context():
        admin_username = 'admin'
        if User.query.filter_by(username=admin_username).first():
            print("Admin user already exists.")
            return
        admin = User(username=admin_username, email='admin@example.com', full_name='Admin User', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{admin_username}' created successfully.")
