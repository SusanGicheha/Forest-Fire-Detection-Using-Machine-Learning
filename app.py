#imports


from flask import Flask
from flask import render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,IntegerField,FloatField
from wtforms.validators import InputRequired,Email,Length,ValidationError
from flask_bootstrap import Bootstrap
from joblib import load
import numpy as np

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) 
Bootstrap(app)
model = load('random_forest.joblib')


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String[80],nullable=False,unique=True)
    username = db.Column(db.String[50], nullable=False)
    password = db.Column(db.String[80], nullable=False)

class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(),Length(min=4,max=90),Email(message='Invalid email')],render_kw={"placeholder":"Email"})
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder":"Password"})

    #submit = SubmitField("Register")

    
    def validate_email(self,email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder":"Password"})

    #submit = SubmitField("Login")

class PredictionForm(FlaskForm):
    month = IntegerField(validators=[InputRequired()],render_kw={'placeholder':'Month in Number ie: 1 (January)'})
    temperature = FloatField(validators=[InputRequired()],render_kw={'placeholder':'Temperature'})
    RH = FloatField(validators=[InputRequired()],render_kw={'placeholder':'Relative Humidity'})
    wind = FloatField(validators=[InputRequired()],render_kw={'placeholder':'Wind Speed'})
    FFMC = FloatField(validators=[InputRequired()],render_kw={'placeholder':'FFMC'})
    DMC = FloatField(validators=[InputRequired()],render_kw={'placeholder':'DMC'})
    DC = FloatField(validators=[InputRequired()],render_kw={'placeholder':'DC'})
    ISI = FloatField(validators=[InputRequired()],render_kw={'placeholder':'ISI'})
    
@app.route("/")
def home():
    #return render_template('home.html')
    return redirect(url_for('login'))

@app.route("/warning")
def warning():
    return render_template('warning.html')

@app.route("/alert")
def alert():
    form = PredictionForm()
    if form.validate_on_submit():
        features = [float(x) for x in request.form.values()]
        final_features = [np.array(features)]
        prediction = model.predict(final_features)

        return render_template('warning.html',prediction_text='{}'.format(prediction)) 
    return render_template('alert.html')

@app.route("/predict",methods=['POST'])
def predict():
    features = [float(x) for x in request.form.values()]
    final_features = [np.array(features)]
    prediction = model.predict(final_features)

    return render_template('warning.html',prediction_text='{}'.format(prediction))

@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
        
    return render_template('login.html',form=form)

@app.route("/dashboard", methods=['GET','POST'])
@login_required
def dashboard():

    return render_template('dashboard.html')



@app.route("/register", methods=['GET','POST'])
def register():
    form =  RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)