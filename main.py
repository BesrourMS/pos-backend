from fastapi import FastAPI, HTTPException, Depends, status, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator, EmailStr, constr
from typing import List, Optional, Dict
from datetime import datetime, timedelta, date
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, ForeignKey, Boolean, and_, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import uuid
import jwt
from passlib.context import CryptContext
from decimal import Decimal
import logging
from logging.handlers import RotatingFileHandler
import traceback
import json

# Security Configuration
SECRET_KEY = "your-secret-key-here"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password handling
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./pos.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Audit Log Configuration
class AuditAction(str, Enum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    SALE = "SALE"
    REPORT = "REPORT"
    ERROR = "ERROR"

# Configure audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
handler = RotatingFileHandler(
    'audit.log',
    maxBytes=10485760,  # 10MB
    backupCount=10
)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

# Database Models
class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)

class ProductDB(Base):
    __tablename__ = "products"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, index=True)
    description = Column(String)
    price = Column(Float)
    stock = Column(Integer)
    min_stock_threshold = Column(Integer, default=10)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, ForeignKey("users.id"))

class SaleDB(Base):
    __tablename__ = "sales"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_amount = Column(Float)
    cashier_id = Column(String, ForeignKey("users.id"))
    payment_method = Column(String)
    items = relationship("SaleItemDB", back_populates="sale")

class SaleItemDB(Base):
    __tablename__ = "sale_items"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    sale_id = Column(String, ForeignKey("sales.id"))
    product_id = Column(String, ForeignKey("products.id"))
    quantity = Column(Integer)
    price_at_sale = Column(Float)
    sale = relationship("SaleDB", back_populates="items")

class AuditLogDB(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String, ForeignKey("users.id"))
    action = Column(String)
    resource_type = Column(String)
    resource_id = Column(String, nullable=True)
    details = Column(String)
    ip_address = Column(String)
    status = Column(String)  # SUCCESS or ERROR
    error_details = Column(String, nullable=True)

# Pydantic Models with Validation
class UserBase(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=50)
    full_name: constr(min_length=1, max_length=100)

class UserCreate(UserBase):
    password: constr(min_length=8)

    @validator('password')
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class User(UserBase):
    id: str
    is_active: bool
    is_admin: bool

    class Config:
        orm_mode = True

class ProductBase(BaseModel):
    name: constr(min_length=1, max_length=100)
    description: constr(min_length=1, max_length=500)
    price: float
    stock: int
    min_stock_threshold: int = 10

    @validator('price')
    def validate_price(cls, v):
        if v <= 0:
            raise ValueError('Price must be greater than zero')
        return round(v, 2)

    @validator('stock')
    def validate_stock(cls, v):
        if v < 0:
            raise ValueError('Stock cannot be negative')
        return v

class ProductCreate(ProductBase):
    pass

class Product(ProductBase):
    id: str
    created_at: datetime
    created_by: str

    class Config:
        orm_mode = True

class SaleItemCreate(BaseModel):
    product_id: str
    quantity: int

    @validator('quantity')
    def validate_quantity(cls, v):
        if v <= 0:
            raise ValueError('Quantity must be greater than zero')
        return v

class SaleItem(SaleItemCreate):
    id: str
    price_at_sale: float

    class Config:
        orm_mode = True

class SaleCreate(BaseModel):
    items: List[SaleItemCreate]
    payment_method: str

    @validator("payment_method")
    def validate_payment_method(cls, value):
        allowed_methods = {"cash", "credit", "debit"}
        if value not in allowed_methods:
            raise ValueError(f"payment_method must be one of {allowed_methods}")
        return value

class Sale(BaseModel):
    id: str
    timestamp: datetime
    total_amount: float
    cashier_id: str
    payment_method: str
    items: List[SaleItem]

    class Config:
        orm_mode = True

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class AuditLog(BaseModel):
    id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: str
    ip_address: str
    status: str
    error_details: Optional[str]

    class Config:
        orm_mode = True

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def log_audit_event(
    db: Session,
    action: AuditAction,
    user_id: str,
    resource_type: str,
    resource_id: Optional[str],
    details: Dict[str, Any],
    request: Request,
    status: str = "SUCCESS",
    error_details: Optional[str] = None
):
    try:
        # Get client IP
        client_ip = request.client.host
        
        # Convert details to JSON string
        details_str = json.dumps(details)
        
        # Create audit log entry
        audit_log = AuditLogDB(
            user_id=user_id,
            action=action.value,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details_str,
            ip_address=client_ip,
            status=status,
            error_details=error_details
        )
        
        db.add(audit_log)
        db.commit()
        
        # Log to file
        audit_logger.info(
            f"AUDIT: {action.value} - User: {user_id} - Resource: {resource_type}"
            f"/{resource_id or 'N/A'} - Status: {status} - IP: {client_ip}"
        )
    except Exception as e:
        audit_logger.error(f"Failed to log audit event: {str(e)}")
        traceback.print_exc()

async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.JWTError:
        await log_audit_event(
            db=db,
            action=AuditAction.ERROR,
            user_id="anonymous",
            resource_type="authentication",
            resource_id=None,
            details={"error": "Invalid token"},
            request=request,
            status="ERROR",
            error_details="Invalid authentication token"
        )
        raise credentials_exception
    
    user = db.query(UserDB).filter(UserDB.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_admin_user(current_user: User = Depends(get_current_active_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    return current_user

app = FastAPI(title="Point of Sale API")

# Authentication endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        await log_audit_event(
            db=db,
            action=AuditAction.LOGIN,
            user_id=form_data.username,
            resource_type="authentication",
            resource_id=None,
            details={"username": form_data.username},
            request=request,
            status="ERROR",
            error_details="Invalid credentials"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.username})
    
    await log_audit_event(
        db=db,
        action=AuditAction.LOGIN,
        user_id=user.id,
        resource_type="authentication",
        resource_id=None,
        details={"username": user.username},
        request=request,
        status="SUCCESS"
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# User management endpoints
@app.post("/users/", response_model=User)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(
        (UserDB.email == user.email) | (UserDB.username == user.username)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = UserDB(**user.dict(exclude={'password'}), hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Product endpoints with validation
@app.post("/products/", response_model=Product)
async def create_product(
    request: Request,
    product: ProductCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    try:
        db_product = ProductDB(**product.dict(), created_by=current_user.id)
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        
        await log_audit_event(
            db=db,
            action=AuditAction.CREATE,
            user_id=current_user.id,
            resource_type="product",
            resource_id=db_product.id,
            details=product.dict(),
            request=request,
            status="SUCCESS"
        )
        
        return db_product
    except Exception as e:
        await log_audit_event(
            db=db,
            action=AuditAction.CREATE,
            user_id=current_user.id,
            resource_type="product",
            resource_id=None,
            details=product.dict(),
            request=request,
            status="ERROR",
            error_details=str(e)
        )
        raise

@app.get("/products/", response_model=List[Product])
def get_products(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(ProductDB).offset(skip).limit(limit).all()

@app.get("/products/{product_id}", response_model=Product)
def get_product(product_id: str, db: Session = Depends(get_db)):
    product = db.query(ProductDB).filter(ProductDB.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@app.put("/products/{product_id}", response_model=Product)
def update_product(product_id: str, product: ProductCreate, db: Session = Depends(get_db)):
    db_product = db.query(ProductDB).filter(ProductDB.id == product_id).first()
    if not db_product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    for key, value in product.dict().items():
        setattr(db_product, key, value)
    
    db.commit()
    db.refresh(db_product)
    return db_product

# Sale endpoints with validation
@app.post("/sales/", response_model=Sale)
async def create_sale(
    request: Request,
    sale: SaleCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    try:
        total_amount = 0
        sale_items = []
        sale_details = []
        
        for item in sale.items:
            product = db.query(ProductDB).filter(ProductDB.id == item.product_id).first()
            if not product:
                raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
            
            if product.stock < item.quantity:
                raise HTTPException(status_code=400, detail=f"Insufficient stock for product {product.name}")
            
            product.stock -= item.quantity
            item_total = product.price * item.quantity
            total_amount += item_total
            
            sale_items.append(SaleItemDB(
                product_id=item.product_id,
                quantity=item.quantity,
                price_at_sale=product.price
            ))
            
            sale_details.append({
                "product_id": product.id,
                "product_name": product.name,
                "quantity": item.quantity,
                "price": product.price,
                "total": item_total
            })
        
        db_sale = SaleDB(
            total_amount=round(total_amount, 2),
            cashier_id=current_user.id,
            payment_method=sale.payment_method
        )
        db.add(db_sale)
        db.flush()
        
        for item in sale_items:
            item.sale_id = db_sale.id
            db.add(item)
        
        db.commit()
        db.refresh(db_sale)
        
        await log_audit_event(
            db=db,
            action=AuditAction.SALE,
            user_id=current_user.id,
            resource_type="sale",
            resource_id=db_sale.id,
            details={
                "total_amount": total_amount,
                "payment_method": sale.payment_method,
                "items": sale_details
            },
            request=request,
            status="SUCCESS"
        )
        
        return db_sale
    except Exception as e:
        await log_audit_event(
            db=db,
            action=AuditAction.SALE,
            user_id=current_user.id,
            resource_type="sale",
            resource_id=None,
            details={
                "payment_method": sale.payment_method,
                "items": [item.dict() for item in sale.items]
            },
            request=request,
            status="ERROR",
            error_details=str(e)
        )
        raise

@app.get("/sales/", response_model=List[Sale])
def get_sales(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(SaleDB).offset(skip).limit(limit).all()
	
@app.get("/sales/{sale_id}", response_model=Sale)
def get_sale(sale_id: str, db: Session = Depends(get_db)):
    sale = db.query(SaleDB).filter(SaleDB.id == sale_id).first()
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    return sale
    
# Reporting endpoints
@app.get("/reports/daily-sales")
async def get_daily_sales(
    start_date: date,
    end_date: date,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    sales = db.query(
        func.date(SaleDB.timestamp).label('date'),
        func.count(SaleDB.id).label('total_transactions'),
        func.sum(SaleDB.total_amount).label('total_amount')
    ).filter(
        and_(
            func.date(SaleDB.timestamp) >= start_date,
            func.date(SaleDB.timestamp) <= end_date
        )
    ).group_by(func.date(SaleDB.timestamp)).all()
    
    return [{
        "date": sale.date,
        "total_transactions": sale.total_transactions,
        "total_amount": round(float(sale.total_amount), 2)
    } for sale in sales]

@app.get("/reports/low-stock")
async def get_low_stock_products(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    products = db.query(ProductDB).filter(
        ProductDB.stock <= ProductDB.min_stock_threshold
    ).all()
    return [{
        "id": product.id,
        "name": product.name,
        "current_stock": product.stock,
        "min_stock_threshold": product.min_stock_threshold
    } for product in products]

@app.get("/reports/sales-by-payment-method")
async def get_sales_by_payment_method(
    start_date: date,
    end_date: date,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    sales = db.query(
        SaleDB.payment_method,
        func.count(SaleDB.id).label('total_transactions'),
        func.sum(SaleDB.total_amount).label('total_amount')
    ).filter(
        and_(
            func.date(SaleDB.timestamp) >= start_date,
            func.date(SaleDB.timestamp) <= end_date
        )
    ).group_by(SaleDB.payment_method).all()
    
    return [{
        "payment_method": sale.payment_method,
        "total_transactions": sale.total_transactions,
        "total_amount": round(float(sale.total_amount), 2)
    } for sale in sales]

# Audit log viewing endpoints (admin only)
@app.get("/audit-logs/", response_model=List[AuditLog])
async def get_audit_logs(
    request: Request,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    action: Optional[AuditAction] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLogDB)
    
    if start_date:
        query = query.filter(func.date(AuditLogDB.timestamp) >= start_date)
    if end_date:
        query = query.filter(func.date(AuditLogDB.timestamp) <= end_date)
    if action:
        query = query.filter(AuditLogDB.action == action)
    if resource_type:
        query = query.filter(AuditLogDB.resource_type == resource_type)
    if user_id:
        query = query.filter(AuditLogDB.user_id == user_id)
    if status:
        query = query.filter(AuditLogDB.status == status)
    
    logs = query.order_by(AuditLogDB.timestamp.desc()).offset(skip).limit(limit).all()
    
    await log_audit_event(
        db=db,
        action=AuditAction.READ,
        user_id=current_user.id,
        resource_type="audit_logs",
        resource_id=None,
        details={
            "start_date": str(start_date) if start_date else None,
            "end_date": str(end_date) if end_date else None,
            "action": action,
            "resource_type": resource_type,
            "user_id": user_id,
            "status": status,
            "skip": skip,
            "limit": limit
        },
        request=request,
        status="SUCCESS"
    )
    
    return logs