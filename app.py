import uuid
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from  flask_marshmallow import Marshmallow
from flask_restful import Resource,Api,abort,reqparse
from flask_httpauth import HTTPBasicAuth
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
app=Flask(__name__)
basedir=os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+os.path.join(basedir,'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY'] = '31b4773a148b17bfe6485149a1be89f9'
db=SQLAlchemy(app)
ma=Marshmallow(app)
class Book(db.Model):
    __tablename__="Books"
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(100))
    author=db.Column(db.String(200))
    price=db.Column(db.Float)
    def serialize(self):
         d={
              'id':self.id,
              'name':self.name,
              'author':self.author,
              'price': self.price,
             }
         return d
class Users(db.Model):
   __tablename__ = "Users"
   id = db.Column(db.Integer, primary_key=True)
   public_id = db.Column(db.Integer)
   name = db.Column(db.String(50))
   password = db.Column(db.String(50))
   admin = db.Column(db.Boolean)
class Products_Schema(ma.Schema):
    class Meta:
        fields=('id','name','author','price')
product_schema=Products_Schema()
products_schema=Products_Schema(many=True)
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']
       if not token:
           return jsonify({'message': 'a valid token is missing please provide the login details to receive the token'})
       data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
       current_user = Users.query.filter_by(public_id=data['public_id']).first()
       # return jsonify({'message': 'token is entered'})
       return f(current_user, *args, **kwargs)
   return decorator

@app.route('/register', methods=['POST'])
def signup_user():
   data = request.get_json()
   hashed_password = generate_password_hash(data['password'], method='sha256')
   new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
   db.session.add(new_user)
   db.session.commit()
   return jsonify({'message': 'registered successfully'})

@app.route('/login', methods=['POST'])
def login_user():
   auth = request.authorization
   print(auth)
   if not auth or not auth.username or not auth.password:
      return make_response('could not verify', 401, {'Authentication': 'login required"'})
   user = Users.query.filter_by(name=auth.username).first()
   if check_password_hash(user.password, auth.password):
      token = jwt.encode(
         {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
         app.config['SECRET_KEY'], "HS256")
      return jsonify({'token': token})
   return make_response('could not verify', 401, {'Authentication': '"login required"'})

@app.route('/users', methods=['GET'])
def get_all_users():
   users = Users.query.all()
   result = []
   for user in users:
      user_data = {}
      user_data['public_id'] = user.public_id
      user_data['name'] = user.name
      user_data['password'] = user.password
      user_data['admin'] = user.admin
      result.append(user_data)
   return jsonify({'users': result})
@app.route('/books/create',methods=['POST'])
@token_required
def add_Book(current_user):
        for prod in request.json:
           new_book =Book()
           new_book.id=prod['id']
           new_book.name=prod['name']
           new_book.author =prod['author']
           new_book.price = prod['price']
           db.session.add(new_book)
           db.session.commit()
           response=jsonify("New book created successfully")
           response.status_code=200
        return response

@app.route('/books',methods=['GET'])
@token_required
def get_books(current_user):
    get_products = Book.query.all()
    product_schema = Products_Schema(many=True)
    products = product_schema.dump(get_products)
    return make_response(jsonify({"product": products}))
@app.route('/books/<id>',methods=['GET'])
@token_required
def get_bookid(current_user,id):
    book = Book.query.get(id)
    if book is None:
        return jsonify({'message': 'ID does not exist'})
    else:
        return product_schema.jsonify(book)

@app.route('/books/<id>',methods=['PUT'])
@token_required
def update_product(current_user,id):
    product=Book.query.get(id)
    if product is None:
        return jsonify({'message': 'ID does not exist'})
    name=request.json['name']
    author = request.json['author']
    price = request.json['price']
    product.name=name
    product.price=price
    product.author=author
    db.session.commit()
    return product_schema.jsonify(product)
@app.route('/books/<id>',methods=['DELETE'])
#@token_required
def delete_bookid(id):
    book=Book.query.get(id)
    if book is None:
        return jsonify({'message': 'ID does not exist'})
    db.session.delete(book)
    db.session.commit()
    return product_schema.jsonify(book)
if __name__=='__main__':
    app.run(debug=True)