import bcrypt
from flask import Flask, jsonify, request
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123@127.0.0.1:3306/user'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)



with app.app_context():
    db.create_all()


@app.route('/create_user')
def create_user():
    new_user = User(username='test', password_hash='1234')
    db.session.add(new_user)
    db.session.commit()
    return 'User created'


login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password_hash)):
            login_user(user)
            return 'Logged in successfully'

    return jsonify({"message": 'Invalid username or password'}), 401

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    if current_user.is_authenticated:
        logout_user()
    return jsonify({"message": "Logout successfully"})


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"message": "User already exists"}), 400
        new_user = User(username=username, password_hash=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    
    return jsonify({"message": "Missing username or password"}), 400


@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def get_user(id_user):
    
    user = User.query.get(id_user)
    
    if user:
        return jsonify({"username": user.username})
    return jsonify({"message": "User not found"}), 404

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    
    user = User.query.get(id_user)
    
    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "You do not have permission to change other users' passwords."}), 403

    if user:
        data = request.json
        password = data.get('password')
        
        if password:
            user.password_hash = password
        
        db.session.commit()
        return jsonify({"message": f"User {id_user} updated successfully"}), 200
    
    return jsonify({"message": "User not found"}), 404


@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    
    user = User.query.get(id_user)


    if current_user.role != 'admin':
        return jsonify({"message": "You do not have permission to delete other users."}), 403
    
    if id_user == current_user.id:
        return jsonify({"message": "It's forbidden delete current user"}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"User {id_user} deleted successfully"}), 200
    
    return jsonify({"message": "User not found"}), 404



if __name__ == '__main__':
    app.run(debug=True)