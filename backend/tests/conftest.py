"""
PREVENT-X Pytest Configuration and Fixtures
Sets up isolated database sessions, seeded RBAC roles, test tenants, and API test clients.
"""

import os
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.database.base import Base
from backend.app.database.session import get_db
from backend.app.main import app
from backend.app.models.organization import Organization
from backend.app.models.role import Role
from backend.app.models.user import OrganizationMembership, User
from backend.app.security.passwords import hash_password
from backend.app.security.permissions import SystemRole
from backend.app.services.bootstrap_service import initialize_system_roles_and_permissions

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not TEST_DATABASE_URL or not TEST_DATABASE_URL.startswith("postgresql"):
    TEST_DATABASE_URL = "sqlite:///:memory:"
    test_engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    test_engine = create_engine(
        TEST_DATABASE_URL,
        pool_pre_ping=True,
    )

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
    expire_on_commit=False,
)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Creates all database tables once for the test session."""
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    try:
        initialize_system_roles_and_permissions(db)
    finally:
        db.close()
    yield
    if not TEST_DATABASE_URL.startswith("postgresql"):
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Yields an isolated transactional session rolled back after test completion."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_tenants(db_session):
    """
    Creates two distinct tenant organizations to test multi-tenancy and data isolation.
    Tenant A: Alpha Corp (slug: alpha-corp)
    Tenant B: Beta Industries (slug: beta-ind)
    """
    org_a = Organization(
        name="Alpha Corp",
        slug="alpha-corp",
        contact_email="security@alphacorp.in",
        sector="Financial Services",
        is_active=True,
    )
    org_b = Organization(
        name="Beta Industries",
        slug="beta-ind",
        contact_email="secops@betaind.in",
        sector="Manufacturing",
        is_active=True,
    )
    db_session.add_all([org_a, org_b])
    db_session.flush()

    # Retrieve roles
    super_admin_role = db_session.query(Role).filter(Role.name == SystemRole.SUPER_ADMIN).first()
    org_admin_role = db_session.query(Role).filter(Role.name == SystemRole.ORG_ADMIN).first()
    analyst_role = db_session.query(Role).filter(Role.name == SystemRole.SECURITY_ANALYST).first()
    viewer_role = db_session.query(Role).filter(Role.name == SystemRole.VIEWER).first()

    # Users
    super_user = User(
        email="superadmin@preventx.internal",
        hashed_password=hash_password("SuperSecretPass123!"),
        full_name="Super Administrator",
        is_active=True,
        is_superuser=True,
    )
    admin_a = User(
        email="admin@alphacorp.in",
        hashed_password=hash_password("AlphaAdminPass123!"),
        full_name="Alpha Admin",
        is_active=True,
        is_superuser=False,
    )
    analyst_a = User(
        email="analyst@alphacorp.in",
        hashed_password=hash_password("AlphaAnalystPass123!"),
        full_name="Alpha Analyst",
        is_active=True,
        is_superuser=False,
    )
    admin_b = User(
        email="admin@betaind.in",
        hashed_password=hash_password("BetaAdminPass123!"),
        full_name="Beta Admin",
        is_active=True,
        is_superuser=False,
    )
    viewer_b = User(
        email="viewer@betaind.in",
        hashed_password=hash_password("BetaViewerPass123!"),
        full_name="Beta Viewer",
        is_active=True,
        is_superuser=False,
    )

    db_session.add_all([super_user, admin_a, analyst_a, admin_b, viewer_b])
    db_session.flush()

    # Memberships
    m_super = OrganizationMembership(user_id=super_user.id, organization_id=org_a.id, role_id=super_admin_role.id, is_default=True)
    m_admin_a = OrganizationMembership(user_id=admin_a.id, organization_id=org_a.id, role_id=org_admin_role.id, is_default=True)
    m_analyst_a = OrganizationMembership(user_id=analyst_a.id, organization_id=org_a.id, role_id=analyst_role.id, is_default=True)
    m_admin_b = OrganizationMembership(user_id=admin_b.id, organization_id=org_b.id, role_id=org_admin_role.id, is_default=True)
    m_viewer_b = OrganizationMembership(user_id=viewer_b.id, organization_id=org_b.id, role_id=viewer_role.id, is_default=True)

    db_session.add_all([m_super, m_admin_a, m_analyst_a, m_admin_b, m_viewer_b])
    db_session.commit()

    return {
        "org_a": org_a,
        "org_b": org_b,
        "super_user": super_user,
        "admin_a": admin_a,
        "analyst_a": analyst_a,
        "admin_b": admin_b,
        "viewer_b": viewer_b,
    }

