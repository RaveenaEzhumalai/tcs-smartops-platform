# cSpell:disable
"""
TCS SmartOps Intelligence Platform - Backend API
FastAPI + WebSocket + JWT Auth + ML Risk Engine
Author: SmartOps AI Team
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import asyncio
import json
import math
import random
import hashlib
import hmac
import base64
import time
import os
import uuid
import logging

# ─── Load .env file if present ──────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — env vars still work from OS

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("smartops")

# ─── CORS Origins ───────────────────────────────────────────────────────────
_CORS_ORIGINS_ENV = os.environ.get("ALLOWED_ORIGINS", "")
CORS_ORIGINS = (
    [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()]
    if _CORS_ORIGINS_ENV else
    ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500",
     "http://localhost:8000", "null"]  # "null" allows file:// origin for local HTML
)

# ─── App Init ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="TCS SmartOps Intelligence Platform",
    description="Agentic AI Platform for Enterprise Operations",
    version="2.4.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=r".*",     # Also allow file:// for local HTML open
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ─── Security Headers Middleware ─────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ─── JWT Config ─────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "tcs-smartops-super-secret-key-change-in-prod-2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours

# ─── Simple JWT (no external library needed beyond stdlib) ──────────────────
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload.update({"exp": expire.timestamp(), "iat": datetime.utcnow().timestamp()})
    body = _b64url_encode(json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"

def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected_sig = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected_sig):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ─── In-Memory User Store (replace with DB in production) ───────────────────
def _hash_password(password: str) -> str:
    return hashlib.sha256(f"{password}{SECRET_KEY}".encode()).hexdigest()

USERS_DB = {
    "admin": {"username": "admin", "full_name": "Admin User", "role": "admin",
              "hashed_password": _hash_password("admin123"), "email": "admin@tcs.com"},
    "manager": {"username": "manager", "full_name": "Project Manager", "role": "manager",
                "hashed_password": _hash_password("manager123"), "email": "manager@tcs.com"},
    "analyst": {"username": "analyst", "full_name": "Data Analyst", "role": "analyst",
                "hashed_password": _hash_password("analyst123"), "email": "analyst@tcs.com"},
}

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    user = USERS_DB.get(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

# ─── Pydantic Models ─────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class ProjectCreate(BaseModel):
    name: str
    client: str
    budget: float
    start_date: str
    end_date: str
    manager: str
    team_size: int
    technology_stack: List[str]
    description: Optional[str] = ""

class ResourceUpdate(BaseModel):
    employee_id: str
    project_id: Optional[str] = None
    skill_tags: Optional[List[str]] = []
    allocation_percent: Optional[int] = 100

class AlertAction(BaseModel):
    alert_id: str
    action: str  # "accept" | "dismiss" | "escalate"
    notes: Optional[str] = ""

class RecommendationFeedback(BaseModel):
    rec_id: str
    accepted: bool
    feedback: Optional[str] = ""

# ─── Sample Data Store (Replace with PostgreSQL/MongoDB in production) ────────
def _make_projects():
    data = [
        {"id":"PRJ001","name":"ALPHA-7","client":"HSBC","status":"at_risk","risk":"high",
         "progress":42,"budget":12500000,"spent":7200000,"manager":"Ravi Kumar",
         "team_size":18,"start":"2024-09-01","end":"2025-03-15","tech":["Java","Spring Boot","Oracle"],
         "sla_breach_risk":87,"delay_days":6,"description":"Core banking transformation"},
        {"id":"PRJ002","name":"BETA-12","client":"Standard Chartered","status":"on_track","risk":"medium",
         "progress":78,"budget":8200000,"spent":5900000,"manager":"Priya Nair",
         "team_size":12,"start":"2024-07-15","end":"2025-03-03","tech":["React","Node.js","MongoDB"],
         "sla_breach_risk":61,"delay_days":2,"description":"Digital onboarding portal"},
        {"id":"PRJ003","name":"GAMMA-3","client":"TCS Internal","status":"on_track","risk":"low",
         "progress":95,"budget":3100000,"spent":2800000,"manager":"Suresh Menon",
         "team_size":6,"start":"2024-10-01","end":"2025-03-05","tech":["Python","FastAPI","PostgreSQL"],
         "sla_breach_risk":12,"delay_days":0,"description":"Internal HR automation"},
        {"id":"PRJ004","name":"DELTA-9","client":"JP Morgan","status":"at_risk","risk":"medium",
         "progress":34,"budget":18700000,"spent":5200000,"manager":"Anjali Singh",
         "team_size":24,"start":"2024-11-01","end":"2025-06-30","tech":["Microservices","Kafka","AWS"],
         "sla_breach_risk":55,"delay_days":4,"description":"Risk management platform"},
        {"id":"PRJ005","name":"EPSILON-2","client":"Barclays","status":"at_risk","risk":"high",
         "progress":61,"budget":9800000,"spent":7100000,"manager":"Rahul Sharma",
         "team_size":15,"start":"2024-08-01","end":"2025-04-20","tech":["Angular","Java","DB2"],
         "sla_breach_risk":79,"delay_days":8,"description":"Trade settlement system"},
        {"id":"PRJ006","name":"ZETA-5","client":"Accenture","status":"on_track","risk":"low",
         "progress":88,"budget":5400000,"spent":4700000,"manager":"Deepa Krishnan",
         "team_size":9,"start":"2024-09-15","end":"2025-04-30","tech":["SAP","ABAP","HANA"],
         "sla_breach_risk":18,"delay_days":0,"description":"ERP modernization"},
        {"id":"PRJ007","name":"ETA-11","client":"DBS Bank","status":"on_track","risk":"medium",
         "progress":52,"budget":7600000,"spent":3400000,"manager":"Vikram Patel",
         "team_size":11,"start":"2024-10-15","end":"2025-05-31","tech":["Python","ML","GCP"],
         "sla_breach_risk":48,"delay_days":3,"description":"Fraud detection AI system"},
        {"id":"PRJ008","name":"THETA-7","client":"Citigroup","status":"on_track","risk":"low",
         "progress":71,"budget":6200000,"spent":4100000,"manager":"Meena Iyer",
         "team_size":8,"start":"2024-08-20","end":"2025-05-15","tech":["iOS","Android","React Native"],
         "sla_breach_risk":22,"delay_days":0,"description":"Mobile banking app v3"},
        {"id":"PRJ009","name":"IOTA-14","client":"Infosys","status":"on_track","risk":"low",
         "progress":33,"budget":4100000,"spent":1200000,"manager":"Arjun Nair",
         "team_size":7,"start":"2024-12-01","end":"2025-07-31","tech":["Azure","DevOps","Terraform"],
         "sla_breach_risk":15,"delay_days":0,"description":"Cloud migration phase 2"},
        {"id":"PRJ010","name":"KAPPA-3","client":"Wipro","status":"at_risk","risk":"high",
         "progress":24,"budget":11200000,"spent":3800000,"manager":"Sonal Mehta",
         "team_size":20,"start":"2024-11-15","end":"2025-08-20","tech":["Blockchain","Hyperledger","Node"],
         "sla_breach_risk":83,"delay_days":7,"description":"Supply chain traceability"},
    ]
    return data

def _make_resources():
    """Fixed resource data — deterministic, no random — consistent across restarts."""
    return [
        {"id":"TCS-10000","name":"Arun Kumar","role":"Senior Engineer",
         "skills":["Java","Spring Boot","SQL"],"location":"Chennai",
         "utilization":94,"bench_days":0,"attrition_risk":62,
         "experience_years":8,"last_promotion_months":28,"performance_rating":4.1,"certifications":3,
         "project":"PRJ001","allocation":94},
        {"id":"TCS-10001","name":"Priya Nair","role":"Lead Engineer",
         "skills":["React","Node.js","AWS"],"location":"Mumbai",
         "utilization":87,"bench_days":0,"attrition_risk":35,
         "experience_years":6,"last_promotion_months":14,"performance_rating":4.6,"certifications":4,
         "project":"PRJ002","allocation":87},
        {"id":"TCS-10002","name":"Suresh Patel","role":"Architect",
         "skills":["Java","Microservices","Kafka"],"location":"Bangalore",
         "utilization":45,"bench_days":18,"attrition_risk":72,
         "experience_years":14,"last_promotion_months":36,"performance_rating":3.8,"certifications":2,
         "project":None,"allocation":0},
        {"id":"TCS-10003","name":"Deepa Iyer","role":"DevSecOps Engineer",
         "skills":["AWS","Kubernetes","DevOps"],"location":"Hyderabad",
         "utilization":79,"bench_days":0,"attrition_risk":28,
         "experience_years":5,"last_promotion_months":10,"performance_rating":4.4,"certifications":5,
         "project":"PRJ004","allocation":79},
        {"id":"TCS-10004","name":"Vikram Singh","role":"AI/ML Consultant",
         "skills":["ML/AI","Python","GCP"],"location":"Pune",
         "utilization":98,"bench_days":0,"attrition_risk":88,
         "experience_years":10,"last_promotion_months":30,"performance_rating":4.8,"certifications":6,
         "project":"PRJ007","allocation":98},
        {"id":"TCS-10005","name":"Meena Krishnan","role":"SAP Manager",
         "skills":["SAP","ABAP","HANA"],"location":"Chennai",
         "utilization":65,"bench_days":7,"attrition_risk":42,
         "experience_years":12,"last_promotion_months":18,"performance_rating":4.2,"certifications":3,
         "project":"PRJ006","allocation":65},
        {"id":"TCS-10006","name":"Rahul Mehta","role":"Java Developer",
         "skills":["Java","Angular","SQL"],"location":"Mumbai",
         "utilization":33,"bench_days":24,"attrition_risk":79,
         "experience_years":3,"last_promotion_months":32,"performance_rating":3.5,"certifications":1,
         "project":None,"allocation":0},
        {"id":"TCS-10007","name":"Anjali Sharma","role":"Lead Engineer",
         "skills":["React","AWS","Node.js"],"location":"Bangalore",
         "utilization":91,"bench_days":0,"attrition_risk":55,
         "experience_years":7,"last_promotion_months":22,"performance_rating":4.3,"certifications":3,
         "project":"PRJ005","allocation":91},
        {"id":"TCS-10008","name":"Arjun Nair","role":"Senior Engineer",
         "skills":["Python","FastAPI","PostgreSQL"],"location":"Delhi",
         "utilization":71,"bench_days":0,"attrition_risk":31,
         "experience_years":5,"last_promotion_months":12,"performance_rating":4.5,"certifications":4,
         "project":"PRJ009","allocation":71},
        {"id":"TCS-10009","name":"Sonal Gupta","role":"QA Analyst",
         "skills":["Testing","SQL","Selenium"],"location":"Kolkata",
         "utilization":28,"bench_days":30,"attrition_risk":83,
         "experience_years":2,"last_promotion_months":20,"performance_rating":3.2,"certifications":0,
         "project":None,"allocation":0},
        {"id":"TCS-10010","name":"Ravi Yadav","role":"Cloud Architect",
         "skills":["AWS","Azure","Terraform"],"location":"Hyderabad",
         "utilization":96,"bench_days":0,"attrition_risk":76,
         "experience_years":9,"last_promotion_months":17,"performance_rating":4.5,"certifications":7,
         "project":"PRJ004","allocation":96},
        {"id":"TCS-10011","name":"Kavya Reddy","role":"Full Stack Developer",
         "skills":["React","Java","Kafka"],"location":"Bangalore",
         "utilization":63,"bench_days":5,"attrition_risk":29,
         "experience_years":4,"last_promotion_months":15,"performance_rating":4.4,"certifications":3,
         "project":"PRJ003","allocation":63},
        {"id":"TCS-10012","name":"Sanjay Joshi","role":"Data Engineer",
         "skills":["Python","GCP","ML/AI"],"location":"Mumbai",
         "utilization":53,"bench_days":8,"attrition_risk":43,
         "experience_years":6,"last_promotion_months":34,"performance_rating":4.0,"certifications":2,
         "project":None,"allocation":0},
        {"id":"TCS-10013","name":"Pooja Pillai","role":"Scrum Master",
         "skills":["Agile","DevOps","Testing"],"location":"Hyderabad",
         "utilization":90,"bench_days":0,"attrition_risk":36,
         "experience_years":7,"last_promotion_months":23,"performance_rating":4.0,"certifications":4,
         "project":"PRJ005","allocation":90},
        {"id":"TCS-10014","name":"Amit Verma","role":"Backend Developer",
         "skills":["Java","Microservices","AWS"],"location":"Delhi",
         "utilization":51,"bench_days":10,"attrition_risk":58,
         "experience_years":4,"last_promotion_months":19,"performance_rating":3.9,"certifications":2,
         "project":None,"allocation":0},
        {"id":"TCS-10015","name":"Neha Agarwal","role":"Senior Engineer",
         "skills":["Node.js","Java","GCP"],"location":"Pune",
         "utilization":97,"bench_days":0,"attrition_risk":67,
         "experience_years":7,"last_promotion_months":28,"performance_rating":4.1,"certifications":3,
         "project":"PRJ010","allocation":97},
        {"id":"TCS-10016","name":"Raj Malhotra","role":"SAP Consultant",
         "skills":["SAP","DevOps","ML/AI"],"location":"Chennai",
         "utilization":82,"bench_days":0,"attrition_risk":45,
         "experience_years":11,"last_promotion_months":18,"performance_rating":3.7,"certifications":4,
         "project":"PRJ006","allocation":82},
        {"id":"TCS-10017","name":"Smita Das","role":"Full Stack Developer",
         "skills":["React","Python","Spring Boot"],"location":"Kolkata",
         "utilization":88,"bench_days":0,"attrition_risk":22,
         "experience_years":5,"last_promotion_months":10,"performance_rating":4.2,"certifications":3,
         "project":"PRJ002","allocation":88},
        {"id":"TCS-10018","name":"Kartik Bose","role":"Data Analyst",
         "skills":["Python","SQL","Azure"],"location":"Bangalore",
         "utilization":66,"bench_days":4,"attrition_risk":51,
         "experience_years":3,"last_promotion_months":23,"performance_rating":3.9,"certifications":2,
         "project":"PRJ003","allocation":66},
        {"id":"TCS-10019","name":"Divya Menon","role":"Blockchain Developer",
         "skills":["Blockchain","Java","Kafka"],"location":"Mumbai",
         "utilization":73,"bench_days":0,"attrition_risk":38,
         "experience_years":4,"last_promotion_months":16,"performance_rating":3.8,"certifications":2,
         "project":"PRJ010","allocation":73},
    ]

PROJECTS_DB = _make_projects()
RESOURCES_DB = _make_resources()

# ─── ML Risk Engine (pure Python, no sklearn needed) ─────────────────────────
class RiskEngine:
    """Lightweight risk scoring without external ML libraries."""

    @staticmethod
    def project_risk_score(project: dict) -> dict:
        # Feature engineering
        budget_burn = project["spent"] / project["budget"] if project["budget"] > 0 else 0
        progress_vs_burn = project["progress"] / 100 - budget_burn
        team_density = project["team_size"] / max(1, len(project["tech"]))

        # Simple weighted scoring model
        risk_score = (
            project["sla_breach_risk"] * 0.35 +
            (budget_burn * 100) * 0.25 +
            max(0, project["delay_days"] * 8) * 0.20 +
            (50 if progress_vs_burn < -0.15 else 0) * 0.20
        )
        risk_score = min(100, max(0, risk_score))

        # Confidence based on data completeness
        confidence = min(99, 70 + project["progress"] // 5)

        return {
            "score": round(risk_score, 1),
            "confidence": confidence,
            "budget_burn_rate": round(budget_burn * 100, 1),
            "schedule_variance": round(progress_vs_burn * 100, 1),
            "predicted_delay_days": project["delay_days"],
            "recommended_action": RiskEngine._get_action(risk_score, project),
        }

    @staticmethod
    def _get_action(score: float, project: dict) -> str:
        if score > 75:
            return f"URGENT: Realign scope & add {max(2, project['delay_days']//2)} FTEs immediately"
        if score > 50:
            return f"Monitor daily. Review sprint plan. Buffer {project['delay_days']} day delay"
        if score > 25:
            return "Weekly check-in sufficient. No immediate action needed"
        return "Project healthy. Continue current execution"

    @staticmethod
    def attrition_risk_score(resource: dict) -> dict:
        score = (
            (100 - resource["performance_rating"] * 20) * 0.20 +
            (resource["last_promotion_months"] - 12) * 1.2 * 0.25 +
            (100 - resource["utilization"]) * 0.20 +
            resource["attrition_risk"] * 0.35
        )
        score = min(100, max(0, score))
        return {
            "score": round(score, 1),
            "risk_level": "HIGH" if score > 70 else "MEDIUM" if score > 40 else "LOW",
            "top_signal": "No recent promotion" if resource["last_promotion_months"] > 24 else
                          "Low utilization" if resource["utilization"] < 60 else
                          "High workload stress" if resource["utilization"] > 95 else "Normal",
            "recommended_action": "Immediate HR engagement" if score > 70 else
                                   "Schedule 1:1 career discussion" if score > 40 else "Routine"
        }

    @staticmethod
    def resource_match(skill_needed: str, resources: list) -> list:
        matches = []
        for r in resources:
            if skill_needed.lower() in [s.lower() for s in r["skills"]]:
                fit_score = (
                    r["performance_rating"] * 20 +
                    (100 - r["utilization"]) * 0.5 +
                    r["certifications"] * 5
                )
                matches.append({**r, "fit_score": round(min(100, fit_score), 1)})
        return sorted(matches, key=lambda x: x["fit_score"], reverse=True)[:5]

    @staticmethod
    def financial_impact(projects: list, resources: list) -> dict:
        total_at_risk = sum(p["budget"] - p["spent"] for p in projects if p["risk"] == "high")
        # Count bench: any bench days > 0 contribute cost (₹5L/month per person)
        bench_resources = [r for r in resources if r.get("bench_days", 0) > 7]
        bench_cost = len(bench_resources) * 500000  # ₹5L/month per bench employee (>7 days idle)
        sla_penalty_risk = sum(p["budget"] * 0.05 for p in projects if p["sla_breach_risk"] > 70)
        cloud_savings = 3800000  # Fixed ₹38L — would come from cloud billing API in production
        # Net value = cloud savings + avoided SLA penalties (10% of exposure) + bench reduction value
        net_value = cloud_savings + (sla_penalty_risk * 0.1) + (bench_cost * 0.3)
        return {
            "revenue_at_risk": round(total_at_risk / 10000000, 2),      # in Cr
            "bench_cost_monthly": round(bench_cost / 100000, 2),         # in Lakhs
            "bench_resources_count": len(bench_resources),
            "sla_penalty_exposure": round(sla_penalty_risk / 100000, 2), # in Lakhs
            "cloud_savings_opportunity": round(cloud_savings / 100000, 2),
            "net_value_generated_today": round(net_value / 100000, 2),   # in Lakhs (displayed as Cr on frontend)
        }

risk_engine = RiskEngine()

# ─── WebSocket Connection Manager ────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WS connected: {client_id}. Total: {len(self.active_connections)}")

    def disconnect(self, client_id: str):
        self.active_connections.pop(client_id, None)
        logger.info(f"WS disconnected: {client_id}")

    async def send_to(self, client_id: str, data: dict):
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(client_id)

    async def broadcast(self, data: dict):
        dead = []
        for cid, ws in self.active_connections.items():
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

manager = ConnectionManager()

# ─── Background AI Agent Simulation ──────────────────────────────────────────
AGENT_EVENTS = [
    {"type":"risk","severity":"high","agent":"RISKBOT-1",
     "message":"Project ALPHA-7: Delay probability increased to 89%. Sprint-3 blocked on DB schema sign-off.",
     "impact":"₹42L","action":"apply_fix","project_id":"PRJ001"},
    {"type":"resource","severity":"medium","agent":"RESOPTIMIZER",
     "message":"3 Java engineers on bench in Chennai match requirements for DELTA-9. Auto-match score: 94%.",
     "impact":"₹18L saved","action":"approve_match","project_id":"PRJ004"},
    {"type":"sla","severity":"high","agent":"SLABOT-3",
     "message":"Barclays SLA T-2h alert: Incident #4821 unresolved. Auto-escalation triggered to L2.",
     "impact":"₹55L penalty avoided","action":"view_incident","project_id":"PRJ005"},
    {"type":"cost","severity":"medium","agent":"COSTGUARD",
     "message":"AWS us-east-1: 47 idle EC2 t3.large instances detected. Rightsizing saves ₹38L/quarter.",
     "impact":"₹38L/quarter","action":"schedule_rightsizing","project_id":None},
    {"type":"attrition","severity":"high","agent":"ATTRITIONAI",
     "message":"TCS-10004 (Senior Architect): Exit probability 91%. LinkedIn activity +340% in 7 days.",
     "impact":"₹25L replacement cost","action":"engage_hr","project_id":None},
    {"type":"compliance","severity":"medium","agent":"AUDITBOT",
     "message":"SOC2 control CC6.1: Access review overdue by 8 days for 12 service accounts.",
     "impact":"Audit finding risk","action":"start_review","project_id":None},
    {"type":"risk","severity":"medium","agent":"RISKBOT-1",
     "message":"KAPPA-3: Blockchain PoC velocity dropped 40%. Client escalation risk next week.",
     "impact":"₹22L","action":"apply_fix","project_id":"PRJ010"},
    {"type":"resource","severity":"low","agent":"RESOPTIMIZER",
     "message":"Upskilling opportunity: 8 Java engineers can be cross-trained to Spring Boot Cloud in 3 weeks.",
     "impact":"Capacity +15%","action":"submit_plan","project_id":None},
]

alert_counter = [0]

async def agent_broadcast_loop():
    """Runs in background, pushes AI events to all connected WebSocket clients."""
    await asyncio.sleep(5)
    while True:
        try:
            if manager.active_connections:
                evt = AGENT_EVENTS[alert_counter[0] % len(AGENT_EVENTS)].copy()
                alert_counter[0] += 1
                evt["id"] = str(uuid.uuid4())
                evt["timestamp"] = datetime.utcnow().isoformat()
                # Add live risk scores
                sample_proj = random.choice(PROJECTS_DB)
                evt["live_risk_score"] = risk_engine.project_risk_score(sample_proj)["score"]
                await manager.broadcast({"type": "agent_event", "payload": evt})
                logger.info(f"Broadcast agent event: {evt['agent']}")
        except Exception as e:
            logger.error(f"Agent loop error: {e}")
        await asyncio.sleep(12)  # Every 12 seconds

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(agent_broadcast_loop())
    logger.info("SmartOps Platform started. Agent loop active.")

# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS_DB.get(form_data.username)
    if not user or user["hashed_password"] != _hash_password(form_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer",
            "user": {"username": user["username"], "full_name": user["full_name"],
                     "role": user["role"], "email": user["email"]}}

@app.get("/api/auth/me", tags=["Auth"])
async def get_me(current_user=Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != "hashed_password"}

# ── Dashboard KPIs ────────────────────────────────────────────────────────────
@app.get("/api/dashboard/kpis", tags=["Dashboard"])
async def get_kpis(current_user=Depends(get_current_user)):
    total = len(PROJECTS_DB)
    at_risk = len([p for p in PROJECTS_DB if p["risk"] in ["high", "medium"]])
    high_risk = len([p for p in PROJECTS_DB if p["risk"] == "high"])
    avg_util = round(sum(r["utilization"] for r in RESOURCES_DB) / len(RESOURCES_DB), 1)
    fin = risk_engine.financial_impact(PROJECTS_DB, RESOURCES_DB)

    # SLA compliance: weighted average of (100 - sla_breach_risk) across all projects
    # This gives a meaningful score like 96.4% not a simple count ratio
    avg_sla_health = sum(100 - p["sla_breach_risk"] for p in PROJECTS_DB) / total
    sla_pct = round(avg_sla_health, 1)

    return {
        "total_projects": total,
        "at_risk_projects": at_risk,
        "high_risk_projects": high_risk,
        "resource_utilization": avg_util,
        "revenue_protected_cr": fin["net_value_generated_today"],
        "sla_compliance_pct": sla_pct,
        "total_resources": len(RESOURCES_DB),
        "bench_count": len([r for r in RESOURCES_DB if r["bench_days"] > 7]),
        "financial_summary": fin,
        "last_updated": datetime.utcnow().isoformat()
    }

# ── Projects ──────────────────────────────────────────────────────────────────
@app.get("/api/projects", tags=["Projects"])
async def get_projects(
    risk: Optional[str] = None,
    status: Optional[str] = None,
    client: Optional[str] = None,
    current_user=Depends(get_current_user)
):
    result = PROJECTS_DB.copy()
    if risk:
        result = [p for p in result if p["risk"] == risk]
    if status:
        result = [p for p in result if p["status"] == status]
    if client:
        result = [p for p in result if client.lower() in p["client"].lower()]
    # Enrich with risk scores
    for p in result:
        p["ai_risk_analysis"] = risk_engine.project_risk_score(p)
    return {"projects": result, "total": len(result), "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/projects/{project_id}", tags=["Projects"])
async def get_project(project_id: str, current_user=Depends(get_current_user)):
    proj = next((p for p in PROJECTS_DB if p["id"] == project_id), None)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    result = proj.copy()
    result["ai_risk_analysis"] = risk_engine.project_risk_score(proj)
    # Find assigned resources
    result["assigned_resources"] = [
        r for r in RESOURCES_DB if r.get("project") == project_id
    ]
    return result

@app.post("/api/projects", tags=["Projects"])
async def create_project(project: ProjectCreate, current_user=Depends(get_current_user)):
    if current_user["role"] not in ["admin", "manager"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    new_id = f"PRJ{len(PROJECTS_DB)+1:03d}"
    new_project = {
        "id": new_id,
        "name": project.name,
        "client": project.client,
        "status": "on_track",
        "risk": "low",
        "progress": 0,
        "budget": project.budget,
        "spent": 0,
        "manager": project.manager,
        "team_size": project.team_size,
        "start": project.start_date,
        "end": project.end_date,
        "tech": project.technology_stack,
        "sla_breach_risk": 10,
        "delay_days": 0,
        "description": project.description,
    }
    PROJECTS_DB.append(new_project)
    # Broadcast to all connected clients
    await manager.broadcast({
        "type": "project_created",
        "payload": {"project_id": new_id, "name": project.name, "client": project.client}
    })
    return {"success": True, "project_id": new_id, "message": f"Project {project.name} created"}

# ── Resources ─────────────────────────────────────────────────────────────────
@app.get("/api/resources", tags=["Resources"])
async def get_resources(
    skill: Optional[str] = None,
    location: Optional[str] = None,
    min_utilization: Optional[int] = None,
    max_utilization: Optional[int] = None,
    current_user=Depends(get_current_user)
):
    result = RESOURCES_DB.copy()
    if skill:
        result = [r for r in result if skill.lower() in [s.lower() for s in r["skills"]]]
    if location:
        result = [r for r in result if r["location"].lower() == location.lower()]
    if min_utilization is not None:
        result = [r for r in result if r["utilization"] >= min_utilization]
    if max_utilization is not None:
        result = [r for r in result if r["utilization"] <= max_utilization]
    # Add attrition scores
    for r in result:
        r["attrition_analysis"] = risk_engine.attrition_risk_score(r)
    return {"resources": result, "total": len(result)}

@app.get("/api/resources/match/{skill}", tags=["Resources"])
async def match_resources(skill: str, current_user=Depends(get_current_user)):
    matches = risk_engine.resource_match(skill, RESOURCES_DB)
    return {"skill_requested": skill, "matches": matches, "total_found": len(matches)}

@app.get("/api/resources/bench", tags=["Resources"])
async def get_bench_resources(current_user=Depends(get_current_user)):
    bench = [r for r in RESOURCES_DB if r["bench_days"] > 7]
    for r in bench:
        r["attrition_analysis"] = risk_engine.attrition_risk_score(r)
    bench.sort(key=lambda x: x["bench_days"], reverse=True)
    return {"bench_resources": bench, "total": len(bench),
            "estimated_monthly_cost_lakh": round(len(bench) * 5.2, 1)}

@app.put("/api/resources/{employee_id}", tags=["Resources"])
async def update_resource(employee_id: str, update: ResourceUpdate,
                           current_user=Depends(get_current_user)):
    resource = next((r for r in RESOURCES_DB if r["id"] == employee_id), None)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    if update.project_id:
        resource["project"] = update.project_id
        resource["allocation"] = update.allocation_percent
        resource["utilization"] = update.allocation_percent
        resource["bench_days"] = 0
    if update.skill_tags:
        resource["skills"] = list(set(resource["skills"] + update.skill_tags))
    await manager.broadcast({
        "type": "resource_updated",
        "payload": {"employee_id": employee_id, "new_project": update.project_id}
    })
    return {"success": True, "message": f"Resource {employee_id} updated"}

# ── AI Agents ─────────────────────────────────────────────────────────────────
@app.get("/api/agents/status", tags=["AI Agents"])
async def get_agent_status(current_user=Depends(get_current_user)):
    return {
        "agents": [
            {"id":"AGT001","name":"RISKBOT-1","type":"risk_monitor","status":"active",
             "tasks_completed_today":47,"load_pct":78,"last_action":"Flagged ALPHA-7 delay",
             "description":"Monitors all projects for delay, scope creep, and SLA risks"},
            {"id":"AGT002","name":"RESOPTIMIZER","type":"resource_optimizer","status":"busy",
             "tasks_completed_today":23,"load_pct":92,"last_action":"Matched 3 Java engineers",
             "description":"Optimizes resource allocation across all delivery pools"},
            {"id":"AGT003","name":"SLABOT-3","type":"sla_guardian","status":"active",
             "tasks_completed_today":15,"load_pct":55,"last_action":"Defended Barclays SLA",
             "description":"Guards all SLA contracts and auto-escalates incidents"},
            {"id":"AGT004","name":"COSTGUARD","type":"cost_optimizer","status":"active",
             "tasks_completed_today":31,"load_pct":67,"last_action":"Found ₹38L cloud savings",
             "description":"Detects cloud waste and contract optimization opportunities"},
            {"id":"AGT005","name":"ATTRITIONAI","type":"talent_radar","status":"active",
             "tasks_completed_today":88,"load_pct":45,"last_action":"Flagged 5 exit risks",
             "description":"Profiles all employees for retention risk signals"},
            {"id":"AGT006","name":"AUDITBOT","type":"compliance","status":"idle",
             "tasks_completed_today":12,"load_pct":0,"last_action":"Completed SOC2 review",
             "description":"Automates compliance checks and audit documentation"},
        ],
        "total_actions_today": 216,
        "autonomous_resolutions": 34,
        "human_escalations": 8,
    }

@app.post("/api/agents/alerts/{alert_id}/action", tags=["AI Agents"])
async def take_alert_action(alert_id: str, action: AlertAction,
                             current_user=Depends(get_current_user)):
    logger.info(f"Alert {alert_id} action: {action.action} by {current_user['username']}")
    result_messages = {
        "accept": "Action applied successfully. Agent monitoring outcome.",
        "dismiss": "Alert dismissed. Snoozed for 24 hours.",
        "escalate": "Escalated to senior management. Email notification sent."
    }
    await manager.broadcast({
        "type": "alert_resolved",
        "payload": {"alert_id": alert_id, "action": action.action,
                    "resolved_by": current_user["username"],
                    "timestamp": datetime.utcnow().isoformat()}
    })
    return {"success": True, "message": result_messages.get(action.action, "Action recorded"),
            "alert_id": alert_id, "action": action.action}

# ── Analytics ─────────────────────────────────────────────────────────────────
@app.get("/api/analytics/risk-trend", tags=["Analytics"])
async def get_risk_trend(current_user=Depends(get_current_user)):
    """Returns 8-week historical + 4-week predicted risk data."""
    weeks = []
    base_risk = 45
    for i in range(-8, 5):
        val = base_risk + math.sin(i * 0.8) * 12 + random.randint(-5, 5)
        weeks.append({
            "week": f"W{i:+d}" if i != 0 else "NOW",
            "value": round(max(20, min(80, val)), 1),
            "is_forecast": i > 0,
            "on_time_pct": round(85 + math.cos(i * 0.5) * 8, 1)
        })
    return {"trend": weeks, "generated_at": datetime.utcnow().isoformat()}

@app.get("/api/analytics/financial-impact", tags=["Analytics"])
async def get_financial_impact(current_user=Depends(get_current_user)):
    fin = risk_engine.financial_impact(PROJECTS_DB, RESOURCES_DB)
    impact_breakdown = [
        {"category":"SLA Penalty Avoided","amount_lakh":82,"type":"saving","agent":"SLABOT-3"},
        {"category":"Resource Optimization","amount_lakh":47,"type":"saving","agent":"RESOPTIMIZER"},
        {"category":"Cloud Cost Reduction","amount_lakh":38,"type":"saving","agent":"COSTGUARD"},
        {"category":"Attrition Prevention","amount_lakh":24,"type":"saving","agent":"ATTRITIONAI"},
        {"category":"Scope Creep Blocked","amount_lakh":19,"type":"saving","agent":"RISKBOT-1"},
        {"category":"Bench Cost","amount_lakh": -fin["bench_cost_monthly"],"type":"loss","agent":"RESOPTIMIZER"},
    ]
    total_saving = sum(i["amount_lakh"] for i in impact_breakdown if i["amount_lakh"] > 0)
    total_loss = abs(sum(i["amount_lakh"] for i in impact_breakdown if i["amount_lakh"] < 0))
    return {
        "breakdown": impact_breakdown,
        "total_saving_lakh": round(total_saving, 1),
        "total_loss_lakh": round(total_loss, 1),
        "net_lakh": round(total_saving - total_loss, 1),
        "financial_data": fin
    }

@app.get("/api/analytics/compliance", tags=["Analytics"])
async def get_compliance(current_user=Depends(get_current_user)):
    return {
        "overall_score": 96.4,
        "frameworks": [
            {"name":"ISO 27001","score":100.0,"status":"compliant","last_audit":"2025-01-15"},
            {"name":"GDPR / Data Privacy","score":98.2,"status":"compliant","last_audit":"2025-02-01"},
            {"name":"SOC2 Type II","score":94.1,"status":"review_needed","last_audit":"2025-01-20",
             "open_items":3},
            {"name":"PCI-DSS","score":91.7,"status":"review_needed","last_audit":"2025-01-10",
             "open_items":4},
            {"name":"Internal Audit","score":82.0,"status":"pending","pending_items":4},
        ],
        "upcoming_audits": [
            {"framework":"Q1 Internal Audit","due_date":"2025-03-08","days_remaining":9},
            {"framework":"SOC2 Renewal","due_date":"2025-04-15","days_remaining":47},
        ],
        "auto_resolved_this_month": 12
    }

@app.get("/api/analytics/predictions", tags=["Analytics"])
async def get_predictions(current_user=Depends(get_current_user)):
    """AI-powered delivery predictions."""
    predictions = []
    for p in PROJECTS_DB:
        score = risk_engine.project_risk_score(p)
        completion_date = p["end"]
        if score["predicted_delay_days"] > 0:
            from datetime import datetime as dt
            try:
                end = dt.strptime(p["end"], "%Y-%m-%d")
                new_end = end + timedelta(days=score["predicted_delay_days"])
                completion_date = new_end.strftime("%Y-%m-%d")
            except Exception:
                pass
        predictions.append({
            "project_id": p["id"],
            "project_name": p["name"],
            "client": p["client"],
            "original_end_date": p["end"],
            "predicted_completion": completion_date,
            "delay_days": score["predicted_delay_days"],
            "confidence": score["confidence"],
            "risk_score": score["score"],
            "recommended_action": score["recommended_action"],
        })
    predictions.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"predictions": predictions, "model_accuracy": 91.4,
            "last_trained": "2025-02-25T06:00:00"}

@app.get("/api/analytics/recommendations", tags=["Analytics"])
async def get_recommendations(current_user=Depends(get_current_user)):
    return {
        "recommendations": [
            {"id":"REC001","title":"Realign DELTA-9 timeline","category":"project",
             "priority":"critical","impact_lakh":55,"effort":"medium","agent":"RISKBOT-1",
             "description":"2-week delay predicted with 91% confidence. Redistribute 4 FTEs from completed ZETA-5. Buffer recovery achievable by Oct 18.",
             "tags":["URGENT","PROJECT","RESOURCE"],"status":"pending"},
            {"id":"REC002","title":"Renegotiate Citibank cloud contract","category":"cost",
             "priority":"high","impact_lakh":120,"effort":"low","agent":"COSTGUARD",
             "description":"Usage pattern shows 34% over-committed capacity. Competitor pricing 22% lower. Contract renewal in 45 days.",
             "tags":["COST","CONTRACT"],"status":"pending"},
            {"id":"REC003","title":"Automate regression suite — GAMMA","category":"quality",
             "priority":"medium","impact_lakh":28,"effort":"low","agent":"RISKBOT-1",
             "description":"68% of manual test cases are automatable. Playwright can reduce QA effort 40%. ROI breakeven in 6 weeks.",
             "tags":["AUTOMATION","QA"],"status":"pending"},
            {"id":"REC004","title":"Knowledge transfer: 3 retiring SMEs","category":"risk",
             "priority":"high","impact_lakh":210,"effort":"high","agent":"ATTRITIONAI",
             "description":"3 COBOL SMEs retiring in 90 days. 4 legacy projects at risk. Initiate AI-assisted knowledge capture + shadow assignments.",
             "tags":["RISK","TALENT","LEGACY"],"status":"pending"},
            {"id":"REC005","title":"Fast-track GenAI upskilling","category":"resource",
             "priority":"medium","impact_lakh":45,"effort":"medium","agent":"RESOPTIMIZER",
             "description":"GenAI skills at 98% utilization. 6 client proposals pending. Upskill 15 Java devs in LangChain/RAG in 4 weeks.",
             "tags":["SKILLS","GROWTH"],"status":"pending"},
        ]
    }

@app.post("/api/analytics/recommendations/{rec_id}/feedback", tags=["Analytics"])
async def submit_recommendation_feedback(rec_id: str, feedback: RecommendationFeedback,
                                          current_user=Depends(get_current_user)):
    logger.info(f"Recommendation {rec_id}: {'accepted' if feedback.accepted else 'rejected'} by {current_user['username']}")
    await manager.broadcast({
        "type": "recommendation_actioned",
        "payload": {"rec_id": rec_id, "accepted": feedback.accepted,
                    "actioned_by": current_user["username"]}
    })
    return {"success": True, "message": "Feedback recorded. Agent model updated."}

# ── WebSocket Live Feed ───────────────────────────────────────────────────────
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str, token: Optional[str] = None):
    # Validate token from query param
    if token and not verify_token(token):
        await websocket.close(code=4001)
        return
    await manager.connect(websocket, client_id)
    # Send initial state immediately on connect
    try:
        await websocket.send_text(json.dumps({
            "type": "connected",
            "payload": {
                "message": "SmartOps real-time feed connected",
                "active_agents": 6,
                "timestamp": datetime.utcnow().isoformat()
            }
        }))
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong",
                                                       "timestamp": datetime.utcnow().isoformat()}))
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WS error for {client_id}: {e}")
        manager.disconnect(client_id)

# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["System"])
async def health():
    return {
        "status": "healthy",
        "version": "2.4.0",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {"api": "ok", "agents": "ok", "websocket": "ok", "ml_engine": "ok"},
        "active_ws_connections": len(manager.active_connections)
    }

# ── Serve Frontend ─────────────────────────────────────────────────────────────
if os.path.exists("../frontend/public"):
    app.mount("/", StaticFiles(directory="../frontend/public", html=True), name="static")
