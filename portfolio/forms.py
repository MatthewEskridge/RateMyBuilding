from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import (BooleanField, DecimalField, IntegerField, PasswordField,
                     SelectField, StringField, SubmitField, TextAreaField,
                     validators)
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                NumberRange, ValidationError)

from portfolio.models import User


class RegisterForm(FlaskForm):

    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')
        
    firstName = StringField(label='Your First Name', validators=[Length(min=2, max=30), DataRequired()])
    lastName = StringField(label='Your Last Name', validators=[Length(min=2, max=30), DataRequired()])
    username = StringField(label='Your User Name', validators=[Length(min=3, max=30), DataRequired()])
    email_address = StringField(label='Your Email', validators=[Email(), DataRequired()])
    password1 = PasswordField(
        label='Password',
        validators=[
            validators.Length(min=8, message="Password must be at least 8 characters long."),
            validators.Regexp(r'^(?=.*\d)', message="Password must contain at least one number."),
            validators.DataRequired(message="Password is required."),
        ])
    
    password2 = PasswordField(label='Confirm Password', validators=[EqualTo('password1'), DataRequired()])
    agree_statement = BooleanField('I agree with all statements', validators=[validators.DataRequired()])
    submit = SubmitField(label='Register')
    
class LoginForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired(message="Username is required")])
    password = PasswordField(label='Password', validators=[DataRequired(message="Password is required")])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField(label='Sign in')

class UpdateEmailForm(FlaskForm):
    new_email = StringField('New Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Email')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField(
        label='Enter Password:',
        validators=[
            validators.Length(min=8, message="Password must be at least 8 characters long."),
            validators.Regexp(r'^(?=.*\d)', message="Password must contain at least one number."),
            validators.DataRequired(message="Password is required."),
        ])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

    def validate_old_password(self, old_password):
        # Check if the old password is correct
        if not current_user.check_password_correction(attempted_password=old_password.data):
            raise ValidationError('Incorrect old password.')
        
class ForgotPasswordForm(FlaskForm):
    email = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    SubmitField = SubmitField('Send')

class ResetPassword(FlaskForm):
    new_password = PasswordField(
        label='Enter Password:',
        validators=[
            validators.Length(min=8, message="Password must be at least 8 characters long."),
            validators.Regexp(r'^(?=.*\d)', message="Password must contain at least one number."),
            validators.DataRequired(message="Password is required."),
        ])
    SubmitField = SubmitField('Submit')

class ReviewForm(FlaskForm):
    
    # For Liam: D:/Comp Sci/[491B]/rate-my-building/building_names.txt
    with open('building_names.txt', 'r') as file:
        building_names = [(line.strip(), line.strip()) for line in file]

    building = SelectField('Building', choices=building_names, validators=[DataRequired()])
    aesthetics = SelectField('Aesthetics', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    cleanliness = SelectField('Cleanliness', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    peripherals = SelectField('Peripherals', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    vibes = SelectField('Vibes', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    content = TextAreaField('Review (max 750 words)', validators=[DataRequired(), Length(max=750)])
    classroom_name = StringField('Classroom Name', validators=[Length(max=50)])
    submit = SubmitField('Submit Review')


class EditReviewForm(FlaskForm):

    aesthetics = SelectField('Aesthetics', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    cleanliness = SelectField('Cleanliness', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    peripherals = SelectField('Peripherals', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    vibes = SelectField('Vibes', choices=[(i, str(i)) for i in range(1, 6)], validators=[DataRequired()])
    content = TextAreaField('Review (max 750 words)', validators=[DataRequired(), Length(max=750)])
    classroom_name = StringField('Classroom Name', validators=[Length(max=50)])
    submit = SubmitField('Submit Review')
