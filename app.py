#imports


from email.policy import default
from flask import Flask,g,session,flash

from flask import render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user,UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import HiddenField,StringField,PasswordField,IntegerField,FloatField
from wtforms.validators import InputRequired,Email,Length,ValidationError,DataRequired,NumberRange
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

class features(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    month = db.Column(db.Integer,nullable=False)
    temp = db.Column(db.Float[20],nullable=False)
    rh = db.Column(db.Float[20],nullable=False)
    wind = db.Column(db.Float[20],nullable=False)
    ffmc = db.Column(db.Float[20],nullable=False)
    dmc = db.Column(db.Float[20],nullable=False)
    isi = db.Column(db.Float[20],nullable=False)
    status = db.Column(db.Integer, nullable=False)


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(),Length(min=4,max=90),Email(message='Invalid email')],render_kw={"placeholder":"Email"})
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder":"Password"})

     
    def validate_email(self,email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20),DataRequired()],render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(min=4, max=20),DataRequired()], render_kw={"placeholder":"Password"})

   

class PredictionForm(FlaskForm):
    user = HiddenField(validators=[DataRequired()])
    month = IntegerField(validators=[NumberRange(min=1,max=12) ,InputRequired(),DataRequired()],render_kw={'placeholder':'Month in Number ie: 1 (January)'})
    temp = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Temperature'})
    rh = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Relative Humidity'})
    wind = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Wind Speed'})
    ffmc = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'FFMC'})
    dmc = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'DMC'})
    isi = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'ISI'})
    
@app.route("/")
def home():
    #return render_template('home.html')
    return redirect(url_for('login'))



@app.route("/inputs", methods=['GET','POST'])
@login_required
def inputs():
    #inputs=None
    form = PredictionForm()
    if form.validate_on_submit():
        return redirect(url_for('dashboard'))
    # if form.validate_on_submit():
    #     # new_entry = [form.month.data,form.temp.data,form.rh.data,form.wind.data,form.ffmc.data,form.dmc.data,form.isi.data]
    #     # predict = [np.array(new_entry)]
    #     # prediction = model.predict(predict)
    #     return redirect(url_for('dashboard'))
    return render_template('inputs.html', form=form)



@app.route("/predict",methods=['POST'])
def predict():
    form = PredictionForm()
    data_features = [form.month.data,form.temp.data,form.rh.data,form.wind.data,form.ffmc.data,form.dmc.data,form.isi.data]
    final_features = [np.array(data_features)]
    prediction = model.predict(final_features)
    #store in db
    new_entry = features(user_id=form.user.data,month=form.month.data,temp=form.temp.data,rh=form.rh.data,wind = form.wind.data,ffmc=form.ffmc.data,dmc=form.dmc.data,isi=form.isi.data,status='{}'.format(prediction))
    db.session.add(new_entry)
    db.session.commit()
    return render_template('dashboard.html',name=session.get("username","Unknown"),prediction_text='{}'.format(prediction))




@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
    
        user = User.query.filter_by(username=form.username.data).first()
        username = form.username.data
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                session['username'] = username
                
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("Incorrect Username - Try Again")
        
    return render_template('login.html',form=form)



@app.route("/dashboard", methods=['GET','POST'])
@login_required
def dashboard():
    
    return render_template('dashboard.html', name=session.get("username","Unknown"))



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