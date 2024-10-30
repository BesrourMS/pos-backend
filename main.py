from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./pos.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class ProductDB(Base):
    __tablename__ = "products"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, index=True)
    description = Column(String)
    price = Column(Float)
    stock = Column(Integer)

class SaleDB(Base):
    __tablename__ = "sales"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_amount = Column(Float)
    items = relationship("SaleItemDB", back_populates="sale")

class SaleItemDB(Base):
    __tablename__ = "sale_items"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    sale_id = Column(String, ForeignKey("sales.id"))
    product_id = Column(String, ForeignKey("products.id"))
    quantity = Column(Integer)
    price_at_sale = Column(Float)
    sale = relationship("SaleDB", back_populates="items")

Base.metadata.create_all(bind=engine)

# Pydantic Models
class ProductBase(BaseModel):
    name: str
    description: str
    price: float
    stock: int

class ProductCreate(ProductBase):
    pass

class Product(ProductBase):
    id: str
    
    class Config:
        orm_mode = True

class SaleItemCreate(BaseModel):
    product_id: str
    quantity: int

class SaleItem(SaleItemCreate):
    id: str
    price_at_sale: float

    class Config:
        orm_mode = True

class SaleCreate(BaseModel):
    items: List[SaleItemCreate]

class Sale(BaseModel):
    id: str
    timestamp: datetime
    total_amount: float
    items: List[SaleItem]

    class Config:
        orm_mode = True

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Point of Sale API")

# Product endpoints
@app.post("/products/", response_model=Product)
def create_product(product: ProductCreate, db: Session = Depends(get_db)):
    db_product = ProductDB(**product.dict())
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

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

# Sale endpoints
@app.post("/sales/", response_model=Sale)
def create_sale(sale: SaleCreate, db: Session = Depends(get_db)):
    # Calculate total amount and create sale items
    total_amount = 0
    sale_items = []
    
    for item in sale.items:
        product = db.query(ProductDB).filter(ProductDB.id == item.product_id).first()
        if not product:
            raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
        
        if product.stock < item.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for product {product.name}")
        
        # Update stock
        product.stock -= item.quantity
        
        # Calculate item total
        item_total = product.price * item.quantity
        total_amount += item_total
        
        # Create sale item
        sale_items.append(SaleItemDB(
            product_id=item.product_id,
            quantity=item.quantity,
            price_at_sale=product.price
        ))
    
    # Create sale
    db_sale = SaleDB(total_amount=total_amount)
    db.add(db_sale)
    db.flush()  # Get the sale ID
    
    # Add items to sale
    for item in sale_items:
        item.sale_id = db_sale.id
        db.add(item)
    
    db.commit()
    db.refresh(db_sale)
    return db_sale

@app.get("/sales/", response_model=List[Sale])
def get_sales(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(SaleDB).offset(skip).limit(limit).all()

@app.get("/sales/{sale_id}", response_model=Sale)
def get_sale(sale_id: str, db: Session = Depends(get_db)):
    sale = db.query(SaleDB).filter(SaleDB.id == sale_id).first()
    if not sale:
        raise HTTPException(status_code=404, detail="Sale not found")
    return sale