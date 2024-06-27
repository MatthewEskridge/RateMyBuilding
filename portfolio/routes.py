from portfolio import app, mail, Message, func
from flask import render_template, redirect, url_for, flash, request, jsonify
from portfolio.models import User, Review,Building_Link
from portfolio.forms import RegisterForm, LoginForm, UpdateEmailForm, ChangePasswordForm, ForgotPasswordForm, ResetPassword, ReviewForm, EditReviewForm
from portfolio import db
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import os
import random
import secrets
import string
from datetime import datetime

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from portfolio import Message, app, db, func, mail
from portfolio.forms import (ChangePasswordForm, EditReviewForm,
                             ForgotPasswordForm, LoginForm, RegisterForm,
                             ResetPassword, ReviewForm, UpdateEmailForm)
from portfolio.models import Review, User


@app.route("/")
@app.route("/home")
def home_page():
    building_names_list = get_building_names_from_file()
    return render_template('home.html', building_names=building_names_list)

@app.route("/register", methods=['POST', 'GET'])
def register_page():

    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            username = form.username.data,
            firstName = form.firstName.data,
            lastName = form.lastName.data,
            email_address = form.email_address.data,
            password = form.password1.data
        )

        db.session.add(user_to_create)
        db.session.commit()

        login_user(user_to_create)
        flash(f"Account created successfully! You are now logged in as {user_to_create.username}", category='success')
        return redirect(url_for('logged_in_page'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)

@app.route("/login", methods=['POST', 'GET'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user:
            if attempted_user.check_password_correction(attempted_password=form.password.data):
                login_user(attempted_user)
                flash(f'Welcome, {attempted_user.username}!', category='success')
                return redirect(url_for('logged_in_page'))
            else:
                flash('Username or password not found. Please try again.', category='danger')
        else:
            flash('Username or password not found. Please try again.', category='danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out. See you again!", category='info')
    return redirect(url_for("home_page"))

@app.route('/logged-in-home')
@login_required
def logged_in_page():
    return render_template('logged_in.html')


@app.route('/update-email', methods=['GET', 'POST'])
@login_required
def update_email():
    form = UpdateEmailForm()
    if form.validate_on_submit():
        # Check if the email is already taken
        existing_user = User.query.filter_by(email_address=form.new_email.data).first()
        if existing_user:
            flash('That email is already taken. Please choose a different one.', category='danger')
            return render_template('update_email.html', form=form)
        
        # Update the email_address attribute of the current_user
        current_user.email_address = form.new_email.data
        # Commit the changes to the database
        db.session.commit()
        flash('Email updated successfully!', category='success')
        return redirect(url_for('account_info'))
    return render_template('update_email.html', form=form)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # Update the user's password
        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully!', category='success')
        return redirect(url_for('account_info'))
    return render_template('change_password.html', form=form)

@app.route('/account-info')
@login_required
def account_info():
    return render_template('account_info.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        send_email_form(form.email.data)
        return redirect(url_for('login_page'))
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>/<email>', methods=['GET', 'POST'])
def password_not_logged_in_page(token, email):
    form = ResetPassword()
    if form.validate_on_submit():
        user = User.query.filter(func.lower(User.email_address) == func.lower(email)).first()

        if user:
            user.password = form.new_password.data
            db.session.commit() 
            flash('Password reset successfully!', category='success')
            return redirect(url_for('login_page'))
        else:
            flash('Invalid user or token.', category='error')

    return render_template('password_not_logged_in_page.html', form=form)


def send_email_form(email):

    token = generate_reset_token()
    msg = Message('Password Reset', sender='ratemybuilding0@gmail.com', recipients=[email])
    msg.body = f'Click the following link to reset your password: {url_for("password_not_logged_in_page", token=token, email=email, _external=True)}'

    try:
        mail.send(msg)
        flash('Password reset instructions sent to your email.', category='success')
    except Exception as e:
        flash('An error occurred while sending the email. Please try again later.', category='error')

def generate_reset_token(length=32):
    characters = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(characters) for _ in range(length))
    return token

@app.route('/review', methods=['GET', 'POST'])
def review_page():
    form = ReviewForm()

    if form.validate_on_submit():
        # Extract the review data from the form and save in database
        review_to_create = Review(
            buildingName = form.building.data,
            aesthetics = int(form.aesthetics.data),
            cleanliness = int(form.cleanliness.data),
            peripherals = int(form.peripherals.data),
            vibes = int(form.vibes.data),
            description = form.content.data,
            room = form.classroom_name.data,
            date_created = datetime.utcnow(),
            owner = current_user.id
        )

        db.session.add(review_to_create)
        db.session.commit()
        flash('Review submitted successfully!', category='success')
        return redirect(url_for('logged_in_page'))

    return render_template('review.html', form=form)

@app.route('/view-user-review/edit/<int:review_id>', methods=['GET', 'POST'])
def edit_user_review(review_id):
    review = Review.query.get_or_404(review_id)
    form = EditReviewForm(obj=review)  # Populate the form with existing review data

    if form.validate_on_submit():
        # Update the review data
        review.aesthetics = int(form.aesthetics.data)
        review.cleanliness = int(form.cleanliness.data)
        review.peripherals = int(form.peripherals.data)
        review.vibes = int(form.vibes.data)
        review.description = form.content.data
        review.date_created = datetime.utcnow()
        review.room = form.classroom_name.data

        db.session.add(review)
        db.session.commit()
        flash('Review updated successfully!', category='success')
        return redirect(url_for('view_user_review'))

    form.content.data = review.description  # Set the initial value for the content field
    return render_template('edit_review.html', form=form, review=review)



@app.route('/view-user-review')
def view_user_review():

    return render_template('user_reviews.html')    

@app.route('/delete_review/<int:id>')
def delete_review(id):
    review_to_delete = Review.query.get_or_404(id)
    
    try: 
        db.session.delete(review_to_delete)
        db.session.commit()
        flash("Review deleted successfully!", category='success')
        return redirect(url_for('view_user_review'))

    except:
        flash("Review not found or unable to delete.", category='error')
        return redirect(url_for('view_user_review'))



import random


# Function to read building names from a file
def get_building_names_from_file():
    with open('building_names.txt', 'r') as f:
        building_names = f.readlines()
    return [name.strip() for name in building_names]

@app.route('/building/<building_name>', methods=['GET'])
def building_profile(building_name):
    reviews = Review.query.filter_by(buildingName=building_name).all()

    total_aesthetics, total_cleanliness, total_peripherals, total_vibes = 0, 0, 0, 0
    total_ratings = len(reviews)  # Calculate the total number of ratings

    for review in reviews:
        total_aesthetics += review.aesthetics
        total_cleanliness += review.cleanliness
        total_peripherals += review.peripherals
        total_vibes += review.vibes

    avg_aesthetics = total_aesthetics / total_ratings if total_ratings > 0 else 0
    avg_cleanliness = total_cleanliness / total_ratings if total_ratings > 0 else 0
    avg_peripherals = total_peripherals / total_ratings if total_ratings > 0 else 0
    avg_vibes = total_vibes / total_ratings if total_ratings > 0 else 0

    overall_quality = (avg_aesthetics + avg_cleanliness + avg_peripherals + avg_vibes) / 4
    overall_quality = round(overall_quality, 1)
    avg_aesthetics = round(avg_aesthetics, 1)
    avg_cleanliness = round(avg_cleanliness, 1)
    avg_peripherals = round(avg_peripherals, 1)
    avg_vibes = round(avg_vibes, 1)

    # Create a list of 4 similar buildings
    similar_buildings = []

    building_names_list = get_building_names_from_file()
    building_link = Building_Link.query.filter_by(buildingName=building_name).first()
    if building_link:
        building_url = building_link.buildingLink
    else:
        building_url = None

    while len(similar_buildings) < 4:
        random_building = random.choice(building_names_list)
        if random_building != building_name and random_building not in [b['building_name'] for b in similar_buildings]:
            # Fetch reviews and calculate ratings for the similar building
            similar_reviews = Review.query.filter_by(buildingName=random_building).all()
            similar_total_ratings = len(similar_reviews)
            if similar_total_ratings > 0:
                similar_avg_aesthetics = sum(review.aesthetics for review in similar_reviews) / similar_total_ratings
                similar_avg_cleanliness = sum(review.cleanliness for review in similar_reviews) / similar_total_ratings
                similar_avg_peripherals = sum(review.peripherals for review in similar_reviews) / similar_total_ratings
                similar_avg_vibes = sum(review.vibes for review in similar_reviews) / similar_total_ratings
                similar_avg_overall_rating = (similar_avg_aesthetics + similar_avg_cleanliness + similar_avg_peripherals + similar_avg_vibes) / 4
            else:
                similar_avg_overall_rating = 0.0

            similar_buildings.append({
                'building_name': random_building,
                'avg_overall_rating': similar_avg_overall_rating,
                'total_ratings': similar_total_ratings,
            })

    return render_template('building_profile.html', 
                           building_name=building_name, 
                           building_url=building_url,
                           avg_overall_rating=overall_quality,  # Pass the overall average rating
                           total_ratings=total_ratings,  # Pass the total number of ratings
                           avg_aesthetics=avg_aesthetics,
                           avg_cleanliness=avg_cleanliness,
                           avg_peripherals=avg_peripherals,
                           avg_vibes=avg_vibes,
                           reviews=reviews,
                           similar_buildings=similar_buildings)


@app.route('/submit_building', methods=['GET'])
def submit_building():
    building_name = request.args.get('building_name')
    return redirect(url_for('building_profile', building_name=building_name))

def get_building_names_from_file():
    """Read building names from the building_names.txtr file."""
    with open('building_names.txt', 'r') as f:
        building_names = f.readlines()
    return [name.strip() for name in building_names]  # Remove any extra spaces or newlines

@app.route('/write_review/<building_name>', methods=['GET'])
@login_required
def write_review(building_name):
    # Create a ReviewForm instance and set the building_name
    form = ReviewForm()
    form.building.data = building_name

    return render_template('review.html', form=form)

@app.route('/search', methods=['GET'])
def search_results():
    # Get the search query from the URL parameter
    search_query = request.args.get('q')

    # Retrieve building names from your text file
    building_names_list = get_building_names_from_file()

    # Filter the building names that match the search query
    search_results = []

    for building_name in building_names_list:
        if search_query.lower() in building_name.lower():
            # Fetch reviews for the building
            reviews = Review.query.filter_by(buildingName=building_name).all()

            total_aesthetics, total_cleanliness, total_peripherals, total_vibes = 0, 0, 0, 0
            total_ratings = len(reviews)  # Calculate the total number of ratings

            for review in reviews:
                total_aesthetics += review.aesthetics
                total_cleanliness += review.cleanliness
                total_peripherals += review.peripherals
                total_vibes += review.vibes

            avg_aesthetics = total_aesthetics / total_ratings if total_ratings > 0 else 0
            avg_cleanliness = total_cleanliness / total_ratings if total_ratings > 0 else 0
            avg_peripherals = total_peripherals / total_ratings if total_ratings > 0 else 0
            avg_vibes = total_vibes / total_ratings if total_ratings > 0 else 0

            overall_quality = (avg_aesthetics + avg_cleanliness + avg_peripherals + avg_vibes) / 4

            # Add the building details and ratings to the search_results list
            search_results.append({
                'building_name': building_name,
                'avg_overall_rating': overall_quality,
                'total_ratings': total_ratings,
                'avg_aesthetics': avg_aesthetics,
                'avg_cleanliness': avg_cleanliness,
                'avg_peripherals': avg_peripherals,
                'avg_vibes': avg_vibes,
            })

    return render_template('search_results.html', search_results=search_results)
@app.route('/like_review/<int:review_id>', methods=['POST'])
@login_required
def like_review(review_id):
    review = Review.query.get_or_404(review_id)

    # Check if the user has already liked the review
    if current_user in review.liked_by:
        # User has already liked, remove the like
        review.likes -= 1
        review.liked_by.remove(current_user)
    else:
        # Check if the user has already disliked the review
        if current_user not in review.disliked_by:
            review.likes += 1
            review.liked_by.append(current_user)

    db.session.commit()
    return jsonify({'likes': review.likes})

@app.route('/dislike_review/<int:review_id>', methods=['POST'])
@login_required
def dislike_review(review_id):
    review = Review.query.get_or_404(review_id)

    # Check if the user has already disliked the review
    if current_user in review.disliked_by:
        # User has already disliked, remove the dislike
        review.dislikes -= 1
        review.disliked_by.remove(current_user)
    else:
        # Check if the user has already liked the review
        if current_user not in review.liked_by:
            review.dislikes += 1
            review.disliked_by.append(current_user)

    db.session.commit()
    return jsonify({'dislikes': review.dislikes})