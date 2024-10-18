import datetime

from flask import Flask, render_template, redirect, url_for, flash, request

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_babel import Babel
app = Flask(__name__)
babel = Babel(app)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///keswa.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
with app.app_context():
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(150), nullable=False)
        phone = db.Column(db.String(20), nullable=False, unique=True)
        password = db.Column(db.String(150), nullable=False)
        email = db.Column(db.String(150), nullable=False, unique=True)
        birthday = db.Column(db.Date, nullable=False)
        role = db.Column(db.String(20), default='customer')
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class MyModelView(ModelView):
    def is_accessible(self):
            return True

admin = Admin(app)

admin.add_view(MyModelView(User, db.session))
@app.route("/")
def start():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        password = request.form.get('password')
        birthday = request.form.get('birthday')
        from datetime import datetime

        birthday = datetime.strptime(birthday, '%Y-%m-%dT%H:%M')


        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
        new_user = User(name=name, phone=phone, password=hashed_password, email=email, birthday=birthday)
        db.session.add(new_user)
        db.session.commit()

        flash('Registered successfully!')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('start'))

        flash('Invalid credentials. Please try again.')

    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('start'))
if __name__=="__main__":
    app.run(debug=True)