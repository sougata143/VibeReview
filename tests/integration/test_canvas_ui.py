# tests/integration/test_canvas_ui.py
import subprocess
import time
import socket
import pytest
from playwright.sync_api import sync_playwright

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

@pytest.fixture(scope="module")
def local_server():
    # Start uvicorn server in background
    proc = subprocess.Popen(
        [".venv/bin/uvicorn", "tests.a2ui_server:app", "--port", "8000", "--log-level", "warning"]
    )
    
    # Wait for the port to open
    retries = 30
    while retries > 0:
        if is_port_open(8000):
            break
        time.sleep(0.2)
        retries -= 1
        
    if retries == 0:
        proc.terminate()
        raise RuntimeError("Failed to start local mock A2UI server on port 8000")
        
    yield "http://localhost:8000"
    
    # Terminate uvicorn
    proc.terminate()
    proc.wait()

def test_canvas_dashboard_correctness(local_server):
    with sync_playwright() as p:
        # Launch browser in headless mode
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # 1. Navigate to localhost
        page.goto(local_server)
        
        # 2. Verify title and static elements
        title_element = page.locator("#title")
        assert "VibeReview Security Audit Report" in title_element.inner_text()
        
        # Verify the list elements are present
        items = page.locator("#vulnerabilities_list li")
        assert items.count() == 3
        
        # 3. Simulate triggering 'Stateful Quarantine' modal
        # Verify modal is hidden initially
        modal = page.locator("#quarantine-modal")
        assert not modal.is_visible()
        
        # Click the button
        page.click("#btn-quarantine")
        
        # Assert modal is visible
        assert modal.is_visible()
        
        # Assert badge status inside modal
        badge = page.locator("#status-badge")
        assert badge.inner_text() == "Status: QUARANTINED"
        
        # Close the modal
        page.click("#btn-close-modal")
        assert not modal.is_visible()
        
        # 4. Simulate 'Vibe Diff' approval workflow
        approval_box = page.locator("#approval-box")
        assert not approval_box.is_visible()
        
        page.click("#btn-approve")
        
        # Assert approval message is visible and matches
        assert approval_box.is_visible()
        assert "Vibe Diff Approved via Cryptographic Hardware MFA" in approval_box.inner_text()
        
        browser.close()
