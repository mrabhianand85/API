from flask import Flask,current_app, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import re

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////project/app.db'

db = SQLAlchemy(app)
app.app_context().push()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class TA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    native_english_speaker = db.Column(db.Boolean)
    course_instructor = db.Column(db.String(50))
    course = db.Column(db.String(50))
    semester = db.Column(db.Boolean)
    class_size = db.Column(db.Integer)
    performance_score = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
      

 
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # token = None
        try:
            authorization = request.headers.get("authorization")
            if re.match("^Bearer *([^ ]+) *$", authorization, flags=0):
                token = authorization.split(" ")[1]
                try:
                    tokendata = jwt.decode(
                    token,app.config['SECRET_KEY'] , algorithms="HS256")
                    current_user = User.query.filter_by(public_id=tokendata['username']).first()
                    print(tokendata)
                except Exception as e:
                    return make_response({"ERROR": "Invalid Token"}, 401)
        except Exception as e:
            return make_response({"Error":"Token Issue Please fill"},500)

        return f(*args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users():



    users = User.query.all()

    output = []
    print(output)

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<id>', methods=['GET'])
@token_required
def get_one_user(id):

  

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/add_user', methods=['POST'])
def create_user():
    try:
        content_type = request.headers.get('Content-Type')
        if (content_type == 'application/json'):
            data=request.json
            print(data)
            hashed_password = generate_password_hash(data['password'], method='sha256')

            new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
            db.session.add(new_user)
            db.session.commit()
            return make_response({"message": 'New User Created Successfully!!'}, 200)
        else:
            return make_response({"message": 'Content-Type not supported!'}, 210)

    except Exception as e:
        print(e)
        return make_response({"message": 'Something Went Wrong'}, 500)
   

@app.route('/user/<id>', methods=['PUT'])
def promote_user(id):

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been updated!'})

@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
   

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})


@app.route("/login", methods=["post"])
def user_login():
    username  = (request.form['username'])
    password = (request.form['password'])
    if not username or not password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, password):
        data={'username' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
        # token = PyJWT.encode(data,key,algorithm="HS256")
        token=jwt.encode(data,app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
  

@app.route('/add/ta', methods=['POST'])
def get_all_tas():
    try:
        content_type = request.headers.get('Content-Type')
        if (content_type == 'application/json'):
            data=request.json
           
            new_record = TA(native_english_speaker=data['native_english_speaker'],course_instructor=data['course_instructor'],course=data['course'], semester=data['semester'], class_size=data['class_size'], performance_score=data['performance_score'], user_id=data['user_id'])
            db.session.add(new_record)
            db.session.commit()
            return make_response({"message": 'New Record inserted Successfully!!'}, 200)
        else:
            return make_response({"message": 'Content-Type not supported!'}, 210)

    except Exception as e:
        print(e)
        return make_response({"message": 'Something Went Wrong'}, 500)
   


@app.route('/single/record/ta/<ta_id>', methods=['GET'])
@token_required
def get_one_ta(ta_id):
    ta = TA.query.filter_by(id=ta_id).first()

    if not ta:
        return jsonify({'message' : 'No ta found!'})

    ta_data = {}
    ta_data['id'] = ta.id
    ta_data['native_english_speaker'] = ta.native_english_speaker
    ta_data['course_instructor'] = ta.course_instructor
    ta_data['course'] = ta.course
    ta_data['semester'] = ta.semester
    ta_data['class_size'] = ta.class_size
    ta_data['performance_score'] = ta.performance_score

    return jsonify(ta_data)

@app.route('/ta', methods=['GET'])
@token_required
def get_all_ta():
    tas = TA.query.all()

    output = []
    print(output)
    
    for ta in tas:
        ta_data = {}
        ta_data['id'] = ta.id
        ta_data['native_english_speaker'] = ta.native_english_speaker
        ta_data['course_instructor'] = ta.course_instructor
        ta_data['course'] = ta.course
        ta_data['semester'] = ta.semester
        ta_data['class_size'] = ta.class_size
        ta_data['performance_score'] = ta.performance_score

    return jsonify({'tas' : output})


@app.route('/ta/<ta_id>', methods=['PUT'])
def update_ta(ta_id):
    
    ta = TA.query.filter_by(id=ta_id).first()

    if not ta:
        return jsonify({'message' : 'No user found!'})

    ta.admin = True
    db.session.commit()

    return jsonify({'message' : 'TA item has been updated!'})

@app.route('/ta/<ta_id>', methods=['DELETE'])
def delete_ta(ta_id):
    
    ta = TA.query.filter_by(id=ta_id).first()

    if not ta:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(ta)
    db.session.commit()

    return jsonify({'message' : 'The record has been deleted!'})
   

if __name__ == '__main__':
    app.run(debug=True)
