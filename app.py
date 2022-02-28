import crypt
from hashlib import scrypt
from flask import Flask, jsonify, request, render_template
from flask_mysqldb import MySQL
from datetime import datetime
import re
import os
from flask_migrate import Migrate
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
import bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "your secret key")
#mysal db connection
app.config['MYSQL_HOST'] = os.environ.get("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.environ.get("MYSQL_USER", "Flask_task_user")
app.config['MYSQL_PASSWORD'] = os.environ.get("MYSQL_PASSWORD", "Flask@123")
app.config['MYSQL_DB'] = os.environ.get("MYSQL_DB", "Flask_task_db")
 
mysql = MySQL(app)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{app.config['MYSQL_USER']}:{app.config['MYSQL_PASSWORD']}" \
                                        f"@{app.config['MYSQL_HOST']}/{app.config['MYSQL_DB']}"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# creates SQLALCHEMY object
db = SQLAlchemy(app)
migrate = Migrate(app, db)



with app.app_context():
    #Creating a connection cursor
    cursor = mysql.connection.cursor()
    
    #Executing SQL Statements
    cursor.execute(''' CREATE TABLE IF NOT EXISTS patient_table (
                        first_name  varchar(20),
                        last_name  varchar(20),
                        cnic_no  varchar(20),
                        date_of_birth  Date,
                        province  varchar(30)
                        ); 
                    ''')
    mysql.connection.commit()
    cursor.close()

def first_name_validation(first_name):
    f_name_is_lower = first_name.islower()
    is_space_not_available = True if ' ' not in first_name else False
    is_length_less_than_21_char = True if len(first_name) < 21 else False

    if f_name_is_lower and is_space_not_available and is_length_less_than_21_char:
        return True
    else :
        return False

def last_name_validation(last_name):
    f_name_is_lower = last_name.islower()
    is_space_not_available = True if ' ' not in last_name else False
    is_length_less_than_21_char = True if len(last_name) < 21 else False

    if f_name_is_lower and is_space_not_available and is_length_less_than_21_char:
        return True
    else :
        return False

def cnic_no_validation(cnic):
    invalid_char = re.search(r'[^\d-]',cnic)
    clean_cnic_no = ''.join(char for char in cnic if char.isdigit())
    is_length_more_than_13_char = True if len(clean_cnic_no) > 13 else False
    if invalid_char or is_length_more_than_13_char:
        return False
    else :
        return True

def province_validation(province):
    valid_province_list = ["sindh", "punjab", "kpk", "gilgit baltistan"]
    province_validation = True if province.lower() in valid_province_list else False
    if province_validation :
        return True
    else :
        return False

def dob_validation(input_dob):
    try:
        date_of_birth = datetime.strptime(input_dob, '%Y-%m-%d').date()
    except:
        return False
    return True


@app.route("/patient", methods =["POST"])
def get_first_name():
    if request.method == "POST":
        input_first_name = request.form.get("fname")
        input_last_name = request.form.get("lname")
        input_cnic = request.form.get("cnic")
        input_dob = request.form.get("dob")
        input_province = request.form.get("province")

        if first_name_validation(input_first_name):
            first_name = True
        else:
            return jsonify({'response':"your first Name is not valid."})
        if last_name_validation(input_last_name):
            last_name = True
        else:
            return jsonify({'response':"your Last Name is not valid."})
        if cnic_no_validation(input_cnic):
            cnic = True
        else:
            return jsonify({'response':"your cnic no is not valid."})
        if dob_validation(input_dob):
            dob = True
        else:
            return jsonify({'response':"your dob is not valid."})
        if province_validation(input_province):
            province = True
        else:
            return jsonify({'response':"your province is not valid."})


        print(first_name,last_name,cnic,dob,province)
        if first_name and last_name and cnic and dob and province:
            cursor = mysql.connection.cursor()
            cursor.execute(''' INSERT INTO patient_table VALUES('{0}','{1}','{2}','{3}','{4}')'''.format(input_first_name,input_last_name,input_cnic,input_dob,input_province))
            
            mysql.connection.commit()
            cursor.close()
            return jsonify({'response':"you data has been saved successfully."})
        else:
            return jsonify({'response':"Invalid data."})

# decorator for verifying the JWT
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query\
				.filter_by(public_id = data['public_id'])\
				.first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		return f(current_user, *args, **kwargs)

	return decorated

class User(db.Model):
    role = db.Column(db.String(50))
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(5000))

@app.route('/student',methods=['POST'])
@token_required
def student(current_user):
    data = request.form
    entered_role = data.get('role')
    if entered_role == 'student':
        return jsonify({'response':"this is the route only for the student role."})
    return jsonify({'response':"you don't have student role."})

@app.route('/admin', methods =['post'])
@token_required
def admin(current_user):
    data = request.form
    entered_role = data.get('role')
    if entered_role == 'admin':
        users = User.query.all()
        output = []
        for user in users:
            output.append({
                'public_id': user.public_id,
                'name' : user.name,
                'email' : user.email
            })
        return jsonify({'users': output})
    return jsonify({'response':"you don't have admin role."})

# route for logging user in
@app.route('/login', methods =['POST'])
def login():
	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):
		# returns 401 if any email or / and password is missing
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		# returns 401 if user does not exist
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, app.config['SECRET_KEY'])

		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
	# creates a dictionary of the form data
	data = request.form
	name, email = data.get('name'), data.get('email')
	password, role = data.get('password'), data.get('role')

	# checking for existing user
	user = User.query.filter_by(email = email).first()
	if not user:
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password, rounds=10),
            # password = password,
            # password= scrypt.hashpw(password.encode('utf-8'), crypt.gensalt()),
            role = role
		)
		db.session.add(user)
		db.session.commit()
		return make_response('Successfully registered.', 201)
	else:
		return make_response('User already exists. Please Log in.', 202)


if __name__ == "__main__":
	app.run(debug = True)

