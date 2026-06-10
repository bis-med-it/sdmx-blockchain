from pydantic import BaseModel

class WalletResponse(BaseModel):
    address: str
    seed: str | None
    public_key: str
    balance_xrp: float
    warning: str | None = None

class WalletLoginRequest(BaseModel):
    address: str

class PublishRequest(BaseModel):
    address: str
    destination: str

class PublishResponse(BaseModel):
    transaction_hash: str
    status: str

class ErrorResponse(BaseModel):
    detail: str
    
class ValidateRequest(BaseModel):
    transaction_hash: str

class ValidateResponse(BaseModel):
    valid: bool
    reason: str | None = None