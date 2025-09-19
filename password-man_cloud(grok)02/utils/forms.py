from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, FileField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, URL, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    master_password = PasswordField('Master Password', validators=[DataRequired(), Length(min=8)])
    totp = StringField('2FA Code (if enabled)', validators=[Optional()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    master_password = PasswordField('Master Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class SearchForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')

class AddPasswordForm(FlaskForm):
    site = StringField('Site', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Add Password')

class EditPasswordForm(FlaskForm):
    site = StringField('Site', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional()])
    submit = SubmitField('Update Password')

class SettingsForm(FlaskForm):
    cloud_url = StringField('Cloud URL', validators=[Optional(), URL()])
    cloud_user = StringField('Cloud Username', validators=[Optional()])
    cloud_pw = PasswordField('Cloud Password', validators=[Optional()])
    enable_2fa = BooleanField('Enable 2FA')
    submit = SubmitField('Save Settings')

class ImportForm(FlaskForm):
    encrypted_vault = TextAreaField('Encrypted Vault Data', validators=[DataRequired()])
    submit = SubmitField('Import Vault')

class CloudUploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')