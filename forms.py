# forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, DateField, TextAreaField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, ValidationError
from modeldb import User
from flask_login import current_user
from flask_babel import lazy_gettext as _l

class LoginForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    submit = SubmitField(_l('Log In'))

class OTPForm(FlaskForm):
    """Form for submitting the OTP token."""
    token = StringField(_l('Token'), validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField(_l('Verify'))

class UserForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired(), Length(min=4, max=25)])
    full_name = StringField(_l('Full Name'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    role = SelectField(_l('Role'), choices=[('member', 'Member'), ('trainer', 'Trainer')], validators=[DataRequired()])
    picture = FileField(_l('Update Profile Picture'), validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    date_of_birth = DateField(_l('Date of Birth'), format='%Y-%m-%d', validators=[Optional()])
    gender = SelectField(_l('Gender'), choices=[('', _l('Select...')), ('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[Optional()])
    intensity = SelectField(_l('Training Intensity'), choices=[('', _l('Select...')), ('Beginner', 'Beginner'), ('Intermediate', 'Intermediate'), ('Advanced', 'Advanced')], validators=[Optional()])
    injuries = TextAreaField(_l('Injuries or Health Conditions'), validators=[Optional()])
    objective = TextAreaField(_l('Member Objective'), validators=[Optional()])
    password = PasswordField(_l('New Password (leave blank to keep current)'), validators=[Optional(), EqualTo('confirm_password', message=_l('Passwords must match.'))])
    confirm_password = PasswordField(_l('Confirm New Password'))
    trainer_id = SelectField(_l('Assign Trainer'), coerce=int, validators=[Optional()])
    is_active = BooleanField(_l('Account Active'), default=True)
    submit = SubmitField(_l('Save User'))

class UpdateAccountForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired(), Length(min=4, max=25)])
    full_name = StringField(_l('Full Name'), validators=[DataRequired()])
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    picture = FileField(_l('Update Profile Picture'), validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField(_l('Update Account'))

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(_l('That username is taken. Please choose a different one.'))

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(_l('That email is taken. Please choose a different one.'))

class BodyMeasurementForm(FlaskForm):
    weight_kg = FloatField(_l('Weight (kg)'), validators=[DataRequired()])
    height_cm = FloatField(_l('Height (cm)'), validators=[DataRequired()])
    body_fat_percentage = FloatField(_l('Body Fat (%%)'), validators=[Optional()])
    muscle_mass_kg = FloatField(_l('Muscle Mass (kg)'), validators=[Optional()])
    bone_mass_kg = FloatField(_l('Bone Mass (kg)'), validators=[Optional()])
    visceral_fat_rating = FloatField(_l('Visceral Fat (Rating)'), validators=[Optional()])
    submit = SubmitField(_l('Submit Report'))

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(_l('Old Password'), validators=[DataRequired()])
    new_password = PasswordField(_l('New Password'), validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message=_l('Passwords must match.'))])
    submit = SubmitField(_l('Change Password'))

class RequestResetForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))

class ResetPasswordForm(FlaskForm):
    password = PasswordField(_l('New Password'), validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message=_l('Passwords must match.'))])
    submit = SubmitField(_l('Reset Password'))