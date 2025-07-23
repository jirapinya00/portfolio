from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import jwt
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    users = db.relationship('User', backref='role', lazy=True)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sales = db.relationship('Sale', backref='user', lazy=True)
    inventory_logs = db.relationship('InventoryLog', backref='user', lazy=True)
    logs = db.relationship('Log', backref='user', lazy=True)

class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sales = db.relationship('Sale', backref='customer', lazy=True)

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    barcode = db.Column(db.String(50), unique=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    cost = db.Column(db.Float, default=0)
    stock_quantity = db.Column(db.Integer, default=0)
    min_stock = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sale_items = db.relationship('SaleItem', backref='product', lazy=True)
    inventory_logs = db.relationship('InventoryLog', backref='product', lazy=True)

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sales = db.relationship('Sale', backref='payment_method', lazy=True)

class Sale(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    sale_number = db.Column(db.String(20), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey('payment_methods.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    discount_amount = db.Column(db.Float, default=0)
    final_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='completed')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sale_items = db.relationship('SaleItem', backref='sale', lazy=True, cascade='all, delete-orphan')

class SaleItem(db.Model):
    __tablename__ = 'sale_items'
    id = db.Column(db.Integer, primary_key=True)
    sale_id = db.Column(db.Integer, db.ForeignKey('sales.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class InventoryLog(db.Model):
    __tablename__ = 'inventory_logs'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(10), nullable=False)  # 'in', 'out', 'adjust'
    quantity_change = db.Column(db.Integer, nullable=False)
    old_quantity = db.Column(db.Integer, nullable=False)
    new_quantity = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(50))
    record_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Discount(db.Model):
    __tablename__ = 'discounts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'percentage', 'fixed'
    value = db.Column(db.Float, nullable=False)
    min_amount = db.Column(db.Float, default=0)
    is_active = db.Column(db.Boolean, default=True)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper functions
def log_action(user_id, action, table_name=None, record_id=None):
    """บันทึก log การกระทำของผู้ใช้"""
    log = Log(
        user_id=user_id,
        action=action,
        table_name=table_name,
        record_id=record_id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def role_required(roles):
    """Decorator ตรวจสอบ role ของผู้ใช้"""
    def decorator(f):
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if not user or user.role.name not in roles:
                return jsonify({'message': 'Access denied'}), 403
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# Routes - HTML Pages
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/pos')
def pos_dashboard():
    return render_template('pos_dashboard.html')

@app.route('/products')
def products_page():
    return render_template('products.html')

@app.route('/users')
def users_page():
    return render_template('users.html')

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

@app.route('/sales-history')
def sale_history():
    return render_template('sale_history.html')

@app.route('/inventory-logs')
def inventory_logs_page():
    return render_template('inventory_logs.html')

@app.route('/reports')
def report_sales():
    return render_template('report_sales.html')

# API Routes - Authentication
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # ตรวจสอบข้อมูล
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'กรุณากรอกข้อมูลให้ครบถ้วน'}), 400
        
        # ตรวจสอบว่ามี username หรือ email นี้แล้วหรือไม่
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'ชื่อผู้ใช้นี้มีอยู่แล้ว'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'อีเมลนี้มีอยู่แล้ว'}), 400
        
        # สร้าง user ใหม่
        password_hash = generate_password_hash(data['password'])
        
        # หา role_id (ถ้าไม่ระบุจะเป็น role_id = 2 คือ staff)
        role_id = data.get('role_id', 2)
        
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=password_hash,
            role_id=role_id
        )
        
        db.session.add(user)
        db.session.commit()
        
        # บันทึก log
        log_action(user.id, 'User registered')
        
        return jsonify({'message': 'สมัครสมาชิกสำเร็จ'}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('password'):
            return jsonify({'message': 'กรุณากรอก username และ password'}), 400
        
        # หา user จาก username หรือ email
        user = User.query.filter(
            (User.username == data['username']) | (User.email == data['username'])
        ).first()
        
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'message': 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'}), 401
        
        if not user.is_active:
            return jsonify({'message': 'บัญชีถูกระงับการใช้งาน'}), 401
        
        # สร้าง JWT token
        access_token = create_access_token(identity=user.id)
        
        # บันทึก log
        log_action(user.id, 'User logged in')
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.name
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'message': 'ไม่พบผู้ใช้'}), 404
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role.name,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

# API Routes - Products
@app.route('/api/products', methods=['GET'])
@jwt_required()
def get_products():
    try:
        products = Product.query.filter_by(is_active=True).all()
        result = []
        
        for product in products:
            result.append({
                'id': product.id,
                'name': product.name,
                'barcode': product.barcode,
                'category': product.category.name,
                'price': product.price,
                'cost': product.cost,
                'stock_quantity': product.stock_quantity,
                'min_stock': product.min_stock
            })
        
        return jsonify({'products': result}), 200
        
    except Exception as e:
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

@app.route('/api/products', methods=['POST'])
@jwt_required()
@role_required(['admin', 'manager'])
def create_product():
    try:
        data = request.get_json()
        current_user_id = get_jwt_identity()
        
        product = Product(
            name=data['name'],
            barcode=data.get('barcode'),
            category_id=data['category_id'],
            price=data['price'],
            cost=data.get('cost', 0),
            stock_quantity=data.get('stock_quantity', 0),
            min_stock=data.get('min_stock', 0)
        )
        
        db.session.add(product)
        db.session.commit()
        
        # บันทึก log
        log_action(current_user_id, 'Product created', 'products', product.id)
        
        return jsonify({'message': 'เพิ่มสินค้าสำเร็จ', 'product_id': product.id}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

# API Routes - Sales
@app.route('/api/sales', methods=['POST'])
@jwt_required()
def create_sale():
    try:
        data = request.get_json()
        current_user_id = get_jwt_identity()
        
        # สร้าง sale number
        from datetime import datetime
        sale_number = f"SALE{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # สร้าง sale
        sale = Sale(
            sale_number=sale_number,
            customer_id=data.get('customer_id'),
            user_id=current_user_id,
            payment_method_id=data['payment_method_id'],
            total_amount=data['total_amount'],
            discount_amount=data.get('discount_amount', 0),
            final_amount=data['final_amount']
        )
        
        db.session.add(sale)
        db.session.flush()  # เพื่อให้ได้ sale.id
        
        # เพิ่ม sale items
        for item in data['items']:
            sale_item = SaleItem(
                sale_id=sale.id,
                product_id=item['product_id'],
                quantity=item['quantity'],
                unit_price=item['unit_price'],
                total_price=item['total_price']
            )
            db.session.add(sale_item)
            
            # อัพเดทสต็อกสินค้า
            product = Product.query.get(item['product_id'])
            old_quantity = product.stock_quantity
            product.stock_quantity -= item['quantity']
            
            # บันทึก inventory log
            inventory_log = InventoryLog(
                product_id=item['product_id'],
                user_id=current_user_id,
                action='out',
                quantity_change=-item['quantity'],
                old_quantity=old_quantity,
                new_quantity=product.stock_quantity,
                reason=f'Sale #{sale_number}'
            )
            db.session.add(inventory_log)
        
        db.session.commit()
        
        # บันทึก log
        log_action(current_user_id, 'Sale created', 'sales', sale.id)
        
        return jsonify({
            'message': 'บันทึกการขายสำเร็จ',
            'sale_id': sale.id,
            'sale_number': sale_number
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'เกิดข้อผิดพลาด: ' + str(e)}), 500

# Initialize database
def init_db():
    """สร้างตารางและข้อมูลเริ่มต้น"""
    with app.app_context():
        db.create_all()
        
        # สร้าง roles เริ่มต้น
        if not Role.query.first():
            admin_role = Role(name='admin', description='ผู้ดูแลระบบ')
            staff_role = Role(name='staff', description='พนักงาน')
            manager_role = Role(name='manager', description='ผู้จัดการ')
            
            db.session.add(admin_role)
            db.session.add(staff_role)
            db.session.add(manager_role)
            db.session.commit()
        
        # สร้าง admin user เริ่มต้น
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                email='admin@pos.com',
                password_hash=generate_password_hash('admin123'),
                role_id=1
            )
            db.session.add(admin_user)
            db.session.commit()
        
        # สร้าง payment methods เริ่มต้น
        if not PaymentMethod.query.first():
            cash = PaymentMethod(name='เงินสด')
            card = PaymentMethod(name='บัตรเครดิต')
            qr = PaymentMethod(name='QR Code')
            
            db.session.add(cash)
            db.session.add(card)
            db.session.add(qr)
            db.session.commit()
        
        # สร้าง categories เริ่มต้น
        if not Category.query.first():
            food = Category(name='อาหาร', description='อาหารทุกประเภท')
            drink = Category(name='เครื่องดื่ม', description='เครื่องดื่มทุกประเภท')
            
            db.session.add(food)
            db.session.add(drink)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)