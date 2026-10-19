import pytest
from app.database import Base, engine, SessionLocal, init_db
from app.models import User, PlanTier
from app.auth import generate_api_key

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Ensure all database tables are created once before test collection/execution."""
    init_db()
    Base.metadata.create_all(bind=engine)
    
    # Provision default CI test user
    db = SessionLocal()
    if not db.query(User).filter(User.email == "test_audit@kubeaudit.local").first():
        user = User(
            email="test_audit@kubeaudit.local",
            api_key="ka_live_mock_ci_test_key",
            subscription_tier=PlanTier.PRO,
            subscription_status="active"
        )
        db.add(user)
        db.commit()
    db.close()
    yield
