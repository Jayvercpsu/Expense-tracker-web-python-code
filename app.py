from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'a1f744f834a2f4c76647e0bffe180790')  # Replace 'your_secret_key' for development

import secrets
secret_key = secrets.token_hex(16)  # Generates a random 32-character hexadecimal string
print(secret_key)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/expense_tracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100))
    expenses = db.relationship('Expense', backref='user', lazy=True)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=False)
    expense_amount = db.Column(db.Float, nullable=False)
    expense_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']  # No hashing here
        full_name = request.form['full_name']

        # Create a new User object
        new_user = User(username=username, email=email, password=password, full_name=full_name)

        # Add the new user to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))  # Redirect to the login page after successful registration
        except Exception as e:
            flash(f'Error: {e}', 'danger')
            db.session.rollback()
            return redirect(url_for('register'))
    
    return render_template('register.html')  # Render the registration form template


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Using get() to avoid KeyError
        password = request.form.get('password')

        if email and password:
            # Query the user by email from the database
            user = User.query.filter_by(email=email).first()

            if user and user.password == password:  # Validate the password
                session['user_id'] = user.id  # Store user_id in session
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Redirect to the dashboard
            else:
                flash('Invalid email or password!', 'danger')
        else:
            flash('Please enter both email and password!', 'danger')

    return render_template('login.html')  # Render the login form


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    user_expenses = Expense.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', expenses=user_expenses)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))  # Redirect to login after logout


@app.route('/add-expense', methods=['GET', 'POST'])
def add_expense():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        category = request.form['category']
        subcategory = request.form['subcategory']
        expense_amount = float(request.form['expense_amount'])
        expense_date = request.form['expense_date']
        description = request.form['description']

        new_expense = Expense(
            category=category,
            subcategory=subcategory,
            expense_amount=expense_amount,
            expense_date=expense_date,
            description=description,
            user_id=session['user_id']
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added successfully.', 'success')
        return redirect(url_for('dashboard'))  # Redirect to dashboard after adding expense

    return render_template('add_expense.html')


@app.route('/delete-expense/<int:expense_id>')
def delete_expense(expense_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id == session['user_id']:
        db.session.delete(expense)
        db.session.commit()
        flash('Expense deleted successfully.', 'success')
    else:
        flash('Unauthorized action.', 'danger')

    return redirect(url_for('dashboard'))  # Redirect to dashboard after deletion


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    flash("Page not found.", 'warning')
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_server_error(e):
    flash("Internal server error. Please try again later.", 'danger')
    return redirect(url_for('index'))


# Run server
if __name__ == '__main__':
    app.run(debug=True)