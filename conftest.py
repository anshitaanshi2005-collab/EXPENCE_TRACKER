import pytest
import sqlite3
import os
import uuid
from app import app as flask_app, init_db
import app as app_module

@pytest.fixture
def app():
    # Configure app for testing
    flask_app.config.update({
        "TESTING": True,
        "JWT_SECRET": "test-secret-key-that-is-at-least-32-bytes-long-for-security",
        "RATELIMIT_ENABLED": False,  # Disable rate limiting for tests
    })
    
    # Use a unique shared in-memory database for this test
    db_name = f"test_{uuid.uuid4().hex}"
    # Force the module-level DB_PATH to use the in-memory URI
    db_uri = f"file:{db_name}?mode=memory&cache=shared"
    app_module.DB_PATH = db_uri
    
    # IMPORTANT: Keep at least one connection open to the in-memory database
    # otherwise it will be destroyed when the last connection closes.
    keep_alive_conn = sqlite3.connect(db_uri, uri=True)
    
    # Initialize the database schema
    with flask_app.app_context():
        init_db()
        
    yield flask_app
    
    # Cleanup: close the keep-alive connection to destroy the in-memory DB
    keep_alive_conn.close()
    
    # No explicit cleanup needed for in-memory DB as it's destroyed when last connection closes
    # But we should ensure all connections are closed if any were leaked.

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def auth_token(client):
    # Helper to get an auth token
    client.post('/api/auth/signup', json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    })
    response = client.post('/api/auth/login', json={
        "username": "testuser",
        "password": "password123"
    })
    return response.get_json()['data']['token']
