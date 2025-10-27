from flask import Flask, render_template, request, redirect, url_for, session, flash
import pickle
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone # <-- NEW: Import for timestamp

app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))

# --- Database & App Configuration ---

app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/insure_predict_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # --- NEW: Relationship to link User to their Predictions ---
    predictions = db.relationship('Prediction', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- NEW: Prediction History Table ---
class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(10), nullable=False)      # Stores "Male" or "Female"
    bmi = db.Column(db.Float, nullable=False)
    children = db.Column(db.Integer, nullable=False)
    smoker = db.Column(db.String(3), nullable=False)     # Stores "Yes" or "No"
    region = db.Column(db.String(20), nullable=False)   # Stores "Northeast", etc.
    predicted_charge_inr = db.Column(db.String(50), nullable=False)
    suggested_plan = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # --- NEW: Foreign Key to link to the User table ---
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Helper Function to Get Plan (No changes) ---
def get_suggested_plan(amount_inr):
    """Categorizes the INR amount into a suggested plan."""
    if amount_inr < 35000:
        return {
            'name': 'Basic Care Plan',
            'description': 'A great, affordable plan for essential coverage, best for young & healthy individuals.'
        }
    elif 35000 <= amount_inr <= 80000:
        return {
            'name': 'Standard Care Plan',
            'description': 'Our most popular plan, offering a balanced mix of coverage and value for comprehensive needs.'
        }
    else: # amount_inr > 80000
        return {
            'name': 'Premium Care Plan',
            'description': 'Complete peace of mind with our all-inclusive coverage, ideal for smokers or those desiring maximum protection.'
        }

# --- Main App Routes ---

@app.route('/home')
@login_required # <-- UPDATED: Protect this page
def home():
    """Renders the main homepage."""
    prediction_text = session.pop('prediction_text', None)
    plan = session.pop('suggested_plan', None)
    
    return render_template("index.html", y=prediction_text, suggested_plan=plan)

@app.route('/predict', methods=['POST'])
@login_required # <-- UPDATED: Protect this action
def predict():
    """Handles the insurance prediction form submission."""
    a = request.form['age']
    b = request.form['sex']
    c = request.form['bmi']
    d = request.form['children']
    e = request.form['smoker']
    f = request.form['region']
    
    # --- Model processing (no changes) ---
    if e.lower() == "yes": e_model = 1
    else: e_model = 0
    
    if b.lower() == "female": b_model = 0
    else: b_model = 1
    
    if f.lower() == "northeast": f_model = 0
    elif f.lower() == "southwest": f_model = 3
    elif f.lower() == "southeast": f_model = 2
    elif f.lower() == "northwest": f_model = 1

    x = [[float(a), float(b_model), float(c), float(d), float(e_model), float(f_model)]]
    output = model.predict(x)[0] # This output is in USD

    INR_ADJUSTMENT_FACTOR = 3.5 
    output_inr = output * INR_ADJUSTMENT_FACTOR
    prediction_text = f"₹{output_inr:,.2f}"
    suggested_plan = get_suggested_plan(output_inr)
    
    # --- NEW: Save the prediction to the database ---
    new_prediction = Prediction(
        age=int(a),
        sex=b,                  # Saves the original "Male" or "Female"
        bmi=float(c),
        children=int(d),
        smoker=e,               # Saves the original "Yes" or "No"
        region=f,               # Saves the original region name
        predicted_charge_inr=prediction_text,
        suggested_plan=suggested_plan['name'],
        user_id=current_user.id # Links to the currently logged-in user
    )
    db.session.add(new_prediction)
    db.session.commit()
    # --- End of new database code ---
    
    session['prediction_text'] = prediction_text
    session['suggested_plan'] = suggested_plan
    
    return redirect(url_for('home'))

# --- UPDATED: Login/Signup/Logout Routes ---

@app.route('/')
def login():
    """Renders the login page."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    """Renders the signup page."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('signup.html')

@app.route('/bmi')
@login_required # <-- UPDATED: Protect this page
def bmi():
    """Renders the BMI calculator page."""
    return render_template('bmi.html')

@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- UPDATED: Form Processing Routes ---

@app.route('/login-process', methods=['POST'])
def login_process():
    """Handles login form submission."""
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
        return redirect(url_for('home'))
    else:
        flash('Invalid username or password. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/signup-process', methods=['POST'])
def signup_process():
    """Handles signup form submission."""
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    # Check if username or email already exists
    user_by_username = User.query.filter_by(username=username).first()
    user_by_email = User.query.filter_by(email=email).first()
    
    if user_by_username:
        flash('Username already exists. Please choose another.', 'danger')
        return redirect(url_for('signup'))
        
    if user_by_email:
        flash('Email address already registered. Please use another.', 'danger')
        return redirect(url_for('signup'))
        
    # Create new user
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('login'))

# --- Create Database Tables ---
with app.app_context():
    db.create_all()

# --- Run the App ---
if __name__ == '__main__':
    app.run(debug=True)

