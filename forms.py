# forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, DateField, TextAreaField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, ValidationError
from modeldb import User
from flask_login import current_user

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class UserForm(FlaskForm):
    """Updated form for admins to add or edit a user with more details."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[('member', 'Member'), ('trainer', 'Trainer')], validators=[DataRequired()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    gender = SelectField('Gender', choices=[('', 'Select...'), ('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], validators=[Optional()])
    intensity = SelectField('Training Intensity', choices=[('', 'Select...'), ('Beginner', 'Beginner'), ('Intermediate', 'Intermediate'), ('Advanced', 'Advanced')], validators=[Optional()])
    injuries = TextAreaField('Injuries or Health Conditions', validators=[Optional()])
    objective = TextAreaField('Member Objective', validators=[Optional()])
    password = PasswordField('Password (leave blank to keep current)', validators=[Optional(), EqualTo('confirm_password', message='Passwords must match.')])
    confirm_password = PasswordField('Confirm Password')
    trainer_id = SelectField('Assign Trainer', coerce=int, validators=[Optional()])
    is_active = BooleanField('Account Active', default=True)
    submit = SubmitField('Save User')

class UpdateAccountForm(FlaskForm):
    """A form for users to update their own account information."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update Account')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class BodyMeasurementForm(FlaskForm):
    """Form for members to submit their monthly measurements."""
    weight_kg = FloatField('Weight (kg)', validators=[DataRequired()])
    height_cm = FloatField('Height (cm)', validators=[DataRequired()])
    body_fat_percentage = FloatField('Body Fat (%)', validators=[Optional()])
    muscle_mass_kg = FloatField('Muscle Mass (kg)', validators=[Optional()])
    bone_mass_kg = FloatField('Bone Mass (kg)', validators=[Optional()])
    visceral_fat_rating = FloatField('Visceral Fat (Rating)', validators=[Optional()])
    submit = SubmitField('Submit Report')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')
