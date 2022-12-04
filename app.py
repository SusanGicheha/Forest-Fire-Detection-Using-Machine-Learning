from flask import Flask,g,session,flash
from flask import render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user,UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import EmailField,StringField,PasswordField,FloatField
from wtforms.validators import InputRequired,Email,Length,ValidationError,DataRequired,NumberRange
from flask_bootstrap import Bootstrap
from joblib import load
import warnings
import datetime
import sqlite3
from sklearn.preprocessing import RobustScaler
warnings.filterwarnings('ignore')

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
    id = db.Column(db.Integer,primary_key=True,unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date=db.Column(db.Date, default=datetime.datetime.utcnow)
    temp = db.Column(db.Float[20],nullable=False)
    rh = db.Column(db.Float[20],nullable=False)
    wind = db.Column(db.Float[20],nullable=False)
    ffmc = db.Column(db.Float[20],nullable=False)
    dmc = db.Column(db.Float[20],nullable=False)
    dc = db.Column(db.Float[20],nullable=False)
    status = db.Column(db.Integer, nullable=False)


class RegisterForm(FlaskForm):
    email = EmailField(validators=[InputRequired(),Length(min=4,max=90)],render_kw={"placeholder":"Email"})
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
   
    #month = IntegerField(validators=[NumberRange(min=1,max=12) ,InputRequired(),DataRequired()],render_kw={'placeholder':'Month in Number ie: 1 (January)'})
    temp = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Temperature'})
    rh = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Relative Humidity'})
    wind = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'Wind Speed'})
    ffmc = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'FFMC'})
    dmc = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'DMC'})
    dc = FloatField(validators=[InputRequired(),DataRequired()],render_kw={'placeholder':'DC'})
    
@app.route("/")
def home():
    #return render_template('home.html')
    return redirect(url_for('landing'))



@app.route("/inputs", methods=['GET','POST'])
@login_required
def inputs():
    #inputs=None
    form = PredictionForm()
    if form.validate_on_submit():
        return redirect(url_for('dashboard'))
 
    return render_template('inputs.html', form=form,name=session.get("username","Unknown"))



@app.route("/predict",methods=['POST'])
@login_required
def predict():
    x = datetime.datetime.now()
    y = x.strftime("%A %b %d, %Y, %I:%M:%S %p")
    form = PredictionForm()
    data_features = [form.temp.data,form.rh.data,form.wind.data,form.ffmc.data,form.dmc.data,form.dc.data]
    prediction = model.predict([data_features])
    if prediction == 1: 
        #store in db
        new_entry = features(user_id=current_user.id,temp=form.temp.data,rh=form.rh.data,wind = form.wind.data,ffmc=form.ffmc.data,dmc=form.dmc.data,dc=form.dc.data,status=1)
        db.session.add(new_entry)
        db.session.commit()
        flash("Status Updated Successfully!")
        #return render_template('dashboard',date=y,name=session.get("username","Unknown"),prediction_text=1)
        return redirect(url_for('inputs'))
    elif prediction == 0: 
        new_entry = features(user_id=current_user.id,temp=form.temp.data,rh=form.rh.data,wind = form.wind.data,ffmc=form.ffmc.data,dmc=form.dmc.data,dc=form.dc.data,status=0)
        db.session.add(new_entry)
        db.session.commit()
        flash("Status Updated Successfully!")
        #return render_template('dashboard',date=y,name=session.get("username","Unknown"),prediction_text=0)
        return redirect(url_for('inputs'))
@app.route("/records", methods=['GET','POST'])
@login_required
def records():
    read_records=features.query.order_by(features.id)
    return render_template('records.html',name=session.get("username","Unknown"),read_records=read_records)


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

@app.route("/landing", methods=['GET','POST'] )
def landing():
    form = LoginForm()
    return render_template("landing.html", form=form)

@app.route("/dashboard", methods=['GET','POST'])
#@login_required
def dashboard():
    x = datetime.datetime.now()
    y = x.strftime("%A %b %d, %Y, %I:%M %p")
    #r_status = features.query.order_by(features.status.desc()).first()
    #r_status = features.query.value(features.status.desc())
    #read_status = cursor.execute('SELECT * FROM features ORDER BY status DESC LIMIT 1;')
    #r_status = read_status.fetchone()
    con = sqlite3.connect('database.db') 
    cur = con.cursor() 
    row = cur.execute('SELECT status FROM features ORDER BY id DESC LIMIT 1;')
    last_row = row.fetchone()
    return render_template('dashboard.html', name=session.get("username","Unknown"), date=y,last_row=last_row)



@app.route("/register", methods=['GET','POST'])
@login_required
def register():
    form =  RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("User Added Successfully! ")
        
    read_users=User.query.order_by(User.id)
    return render_template('register.html',form=form,read_users=read_users)

@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('landing'))


if __name__ == '__main__':
    app.run(debug=True)