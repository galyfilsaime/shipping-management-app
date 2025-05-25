from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
# Use absolute path for SQLite database
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data', 'shipping.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'  # Replace with a secure key
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable for simplicity; enable in production
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Predefined shipment statuses
SHIPMENT_STATUSES = ['Pending', 'Shipped', 'In Transit', 'Delivered', 'Cancelled']

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    shipments = db.relationship('Shipment', backref='user', lazy=True)

class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_number = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    origin = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    expedited = db.Column(db.Boolean, default=False)
    payment_status = db.Column(db.String(20), default='Pending')

class ShipmentHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shipment_id = db.Column(db.Integer, db.ForeignKey('shipment.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    shipment = db.relationship('Shipment', backref=db.backref('history', lazy=True))

class UserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('user_history', lazy=True))

# Ensure database directory exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Context processor to make user_role available to all templates
@app.context_processor
def inject_user_role():
    try:
        jwt_data = get_jwt()
        if jwt_data:
            return {'user_role': jwt_data.get('role')}
        return {'user_role': None}
    except:
        return {'user_role': None}

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.username, additional_claims={'role': user.role})
            session['role'] = user.role
            response = make_response(redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('dashboard')))
            response.set_cookie('access_token_cookie', access_token, httponly=True, secure=False)
            return response
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token_cookie', '', expires=0)
    flash('Logged out successfully', 'success')
    return response

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('logout'))

    # Get filter parameters
    status = request.args.get('status')
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    expedited = request.args.get('expedited')
    payment_status = request.args.get('payment_status')
    
    query = Shipment.query.filter_by(user_id=user.id)
    if status:
        query = query.filter_by(status=status)
    if origin:
        query = query.filter(Shipment.origin.ilike(f'%{origin}%'))
    if destination:
        query = query.filter(Shipment.destination.ilike(f'%{destination}%'))
    if expedited:
        query = query.filter_by(expedited=expedited == 'true')
    if payment_status:
        query = query.filter_by(payment_status=payment_status)
    
    shipments = query.all()
    statuses = ['Pending', 'In Transit', 'Delivered', 'Cancelled']
    payment_statuses = ['Pending', 'Paid']
    return render_template('dashboard.html', shipments=shipments, statuses=statuses, payment_statuses=payment_statuses)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         

@app.route('/expedite/<tracking_number>', methods=['POST'])
@jwt_required()
def expedite(tracking_number):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    shipment = Shipment.query.filter_by(tracking_number=tracking_number, user_id=user.id).first()
    
    if not shipment:
        flash('Shipment not found or not assigned to you', 'danger')
        return redirect(url_for('dashboard'))
    
    if shipment.expedited:
        flash('Shipment is already expedited', 'warning')
    else:
        shipment.expedited = True
        shipment.last_updated = datetime.utcnow()
        db.session.commit()
        history = ShipmentHistory(
            shipment_id=shipment.id,
            action='Expedited',
            details='Shipment marked as expedited',
            timestamp=datetime.utcnow()
        )
        db.session.add(history)
        db.session.commit()
        flash('Shipment expedited successfully', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/pay/<tracking_number>', methods=['POST'])
@jwt_required()
def pay(tracking_number):
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    shipment = Shipment.query.filter_by(tracking_number=tracking_number, user_id=user.id).first()
    
    if not shipment:
        flash('Shipment not found or not assigned to you', 'danger')
        return redirect(url_for('dashboard'))
    
    if shipment.payment_status == 'Paid':
        flash('Shipment is already paid', 'warning')
    else:
        # Simulate payment processing (replace with actual payment gateway in production)
        shipment.payment_status = 'Paid'
        shipment.last_updated = datetime.utcnow()
        db.session.commit()
        history = ShipmentHistory(
            shipment_id=shipment.id,
            action='Paid',
            details='Shipment payment status changed to Paid',
            timestamp=datetime.utcnow()
        )
        db.session.add(history)
        db.session.commit()
        flash('Payment processed successfully', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/track', methods=['GET', 'POST'])
def track():
    shipment = None
    if request.method == 'POST':
        tracking_number = request.form['tracking_number']
        shipment = Shipment.query.filter_by(tracking_number=tracking_number).first()
        if not shipment:
            flash('Shipment not found', 'danger')
    return render_template('track.html', shipment=shipment)

@app.route('/shipment_history/<tracking_number>')
@jwt_required()
def shipment_history(tracking_number):
    shipment = Shipment.query.filter_by(tracking_number=tracking_number).first()
    if not shipment:
        return jsonify({'error': 'Shipment not found'}), 404
    history = ShipmentHistory.query.filter_by(shipment_id=shipment.id).order_by(ShipmentHistory.timestamp.desc()).all()
    history_data = [{
        'action': h.action,
        'details': h.details,
        'timestamp': h.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for h in history]
    return jsonify(history_data)

@app.route('/user_history/<int:user_id>')
@jwt_required()
def user_history(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    history = UserHistory.query.filter_by(user_id=user_id).order_by(UserHistory.timestamp.desc()).all()
    history_data = [{
        'action': h.action,
        'details': h.details,
        'timestamp': h.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    } for h in history]
    return jsonify(history_data)

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@jwt_required()
def admin_dashboard():
    jwt_data = get_jwt()
    if jwt_data['role'] != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('track'))
    
    statuses = ['Pending', 'In Transit', 'Delivered', 'Cancelled']
    payment_statuses = ['Pending', 'Paid']
    users = User.query.all()
    status = request.args.get('status')
    origin = request.args.get('origin')
    destination = request.args.get('destination')
    user_id = request.args.get('user_id')
    expedited = request.args.get('expedited')
    payment_status = request.args.get('payment_status')
    
    query = Shipment.query
    if status:
        query = query.filter_by(status=status)
    if origin:
        query = query.filter(Shipment.origin.ilike(f'%{origin}%'))
    if destination:
        query = query.filter(Shipment.destination.ilike(f'%{destination}%'))
    if user_id:
        query = query.filter_by(user_id=user_id)
    if expedited:
        query = query.filter_by(expedited=expedited == 'true')
    if payment_status:
        query = query.filter_by(payment_status=payment_status)
    
    shipments = query.all()
    
    if request.method == 'POST' and 'shipment_action' in request.form:
        action = request.form.get('shipment_action')
        tracking_number = request.form['tracking_number']
        status = request.form['status']
        origin = request.form['origin']
        destination = request.form['destination']
        user_id = request.form['user_id'] if request.form['user_id'] else None
        
        shipment = Shipment.query.filter_by(tracking_number=tracking_number).first()
        
        if action == 'create':
            if shipment:
                flash('Tracking number already exists', 'danger')
            else:
                new_shipment = Shipment(
                    tracking_number=tracking_number,
                    status=status,
                    origin=origin,
                    destination=destination,
                    user_id=user_id,
                    last_updated=datetime.utcnow()
                )
                db.session.add(new_shipment)
                db.session.commit()
                history = ShipmentHistory(
                    shipment_id=new_shipment.id,
                    action='Created',
                    details=f'Shipment created with status {status}, origin {origin}, destination {destination}',
                    timestamp=datetime.utcnow()
                )
                db.session.add(history)
                db.session.commit()
                flash('Shipment created', 'success')
        
        elif action == 'update' and shipment:
            old_status = shipment.status
            old_user_id = shipment.user_id
            shipment.status = status
            shipment.origin = origin
            shipment.destination = destination
            shipment.user_id = user_id
            shipment.last_updated = datetime.utcnow()
            db.session.commit()
            history = ShipmentHistory(
                shipment_id=shipment.id,
                action='Updated',
                details=f'Status changed from {old_status} to {status}, origin to {origin}, destination to {destination}, user_id to {user_id or "None"}',
                timestamp=datetime.utcnow()
            )
            db.session.add(history)
            db.session.commit()
            flash('Shipment updated', 'success')
        
        elif action == 'delete' and shipment:
            history = ShipmentHistory(
                shipment_id=shipment.id,
                action='Deleted',
                details=f'Shipment with status {shipment.status} deleted',
                timestamp=datetime.utcnow()
            )
            db.session.add(history)
            db.session.delete(shipment)
            db.session.commit()
            flash('Shipment deleted', 'success')
        
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST' and 'user_action' in request.form:
        action = request.form.get('user_action')
        user_id = request.form.get('user_id')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        if action == 'create':
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
            elif User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, email=email, password=hashed_password, role=role)
                db.session.add(new_user)
                db.session.commit()
                history = UserHistory(
                    user_id=new_user.id,
                    action='Created',
                    details=f'User created with username {username}, email {email}, role {role}',
                    timestamp=datetime.utcnow()
                )
                db.session.add(history)
                db.session.commit()
                flash('User created', 'success')
        
        elif action == 'update' and user_id:
            user = User.query.get(user_id)
            if not user:
                flash('User not found', 'danger')
            elif User.query.filter_by(username=username).filter(User.id != user_id).first():
                flash('Username already exists', 'danger')
            elif User.query.filter_by(email=email).filter(User.id != user_id).first():
                flash('Email already exists', 'danger')
            else:
                old_username = user.username
                old_email = user.email
                old_role = user.role
                user.username = username
                user.email = email
                user.role = role
                if password:
                    user.password = generate_password_hash(password, method='pbkdf2:sha256')
                db.session.commit()
                history = UserHistory(
                    user_id=user.id,
                    action='Updated',
                    details=f'Username changed from {old_username} to {username}, email from {old_email} to {email}, role from {old_role} to {role}{", password updated" if password else ""}',
                    timestamp=datetime.utcnow()
                )
                db.session.add(history)
                db.session.commit()
                flash('User updated', 'success')
        
        elif action == 'delete' and user_id:
            user = User.query.get(user_id)
            if not user:
                flash('User not found', 'danger')
            elif user.role == 'admin':
                flash('Cannot delete admin account', 'danger')
            else:
                history = UserHistory(
                    user_id=user.id,
                    action='Deleted',
                    details=f'User with username {user.username} deleted',
                    timestamp=datetime.utcnow()
                )
                db.session.add(history)
                db.session.delete(user)
                db.session.commit()
                flash('User deleted', 'success')
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_dashboard.html', shipments=shipments, users=users, statuses=statuses, payment_statuses=payment_statuses)

if __name__ == '__main__':
    app.run(debug=True)