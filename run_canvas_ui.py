#!/usr/bin/env python3
# run_canvas_ui.py
# Frontend Canvas UI simulator for VibeReview.

import sys
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set mock environment variables for offline execution safety if not explicitly set
os.environ.setdefault("INTEGRATION_TEST", "TRUE")

# Mock Google Auth Default globally for local/offline run support
import google.auth
import google.auth.credentials

class DummyCredentials(google.auth.credentials.Credentials):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = "dummy-token"
    def refresh(self, request):
        pass

google.auth.default = lambda **kwargs: (DummyCredentials(), "dummy-project")

from app.agent_runtime_app import agent_runtime

def render_a2ui_dashboard(payload: dict):
    surface_id = payload.get("surfaceId", "default-surface")
    components = payload.get("components", [])
    
    print("\n" + "="*70)
    print(f"🎨 CANVAS UI SIMULATOR (Surface ID: {surface_id})")
    print("="*70)
    
    if not components:
        print("[No UI components returned to map]")
        print("="*70 + "\n")
        return
        
    # Map components by ID for quick tree traversal
    comp_map = {}
    for comp in components:
        c_id = comp.get("id")
        if c_id:
            comp_map[c_id] = comp
            
    # Find root component (usually "root" or first component in list)
    root_id = "root" if "root" in comp_map else (components[0].get("id") if components else None)
    
    rendered_ids = set()
    
    def render_node(node_id: str, indent: int = 0):
        if not node_id or node_id in rendered_ids:
            return
        rendered_ids.add(node_id)
        
        comp = comp_map.get(node_id)
        if not comp:
            # Maybe the child ID refers to a list item or text literal, print as raw child reference
            print("  " * indent + f"└─ [Missing node: '{node_id}']")
            return
            
        comp_type = comp.get("component") or comp.get("type") or "Unknown"
        
        # Properties can be flat at root or nested under properties dict
        properties = comp.get("properties", {})
        text = comp.get("text") or properties.get("text") or ""
        variant = comp.get("variant") or properties.get("variant") or ""
        
        spacing = "  " * indent
        
        # Map JSON components into visual stdout elements
        if comp_type == "Card":
            print(f"{spacing}┌───────────────────────────────────────────────┐")
            print(f"{spacing}│ 🗂️  [Card id='{node_id}'] component block       │")
            print(f"{spacing}└───────────────────────────────────────────────┘")
        elif comp_type == "Header" or comp_type == "Title":
            print(f"{spacing}📢 [Header: '{text}'] ({variant or 'h1'})")
        elif comp_type == "Text":
            if variant.startswith("h"):
                print(f"{spacing}✏️  [Title variant='{variant}'] -> {text}")
            else:
                print(f"{spacing}📝 {text}")
        elif comp_type == "List":
            print(f"{spacing}☰  [List id='{node_id}'] vertical stack:")
            items = comp.get("items") or properties.get("items")
            if items and isinstance(items, list):
                for item in items:
                    print(f"{spacing}  🔸 {item}")
        elif comp_type == "Button":
            print(f"{spacing}🔘 [ {text.upper() or 'SUBMIT'} ]")
        elif comp_type == "Container":
            print(f"{spacing}📦 [Container id='{node_id}'] wrapper")
        else:
            print(f"{spacing}⚙️  [{comp_type} id='{node_id}'] text='{text}'")
            
        # Traverse children/child elements
        children = []
        if "child" in comp:
            children.append(comp["child"])
        elif "children" in comp:
            if isinstance(comp["children"], list):
                children.extend(comp["children"])
        elif "child" in properties:
            children.append(properties["child"])
        elif "children" in properties:
            if isinstance(properties["children"], list):
                children.extend(properties["children"])
                
        for child_id in children:
            render_node(child_id, indent + 1)

    if root_id:
        render_node(root_id, 0)
    else:
        print("[No root node resolved]")
        
    print("="*70 + "\n")

def run_canvas_ui(prompt: str):
    print(f"Requesting UI canvas update with prompt: '{prompt}'...")
    
    # Invoke VibeReview pipeline stream
    accumulated_text = ""
    for event in agent_runtime.stream_query(message=prompt, user_id="canvas-ui-client"):
        content = event.get("content")
        if content and "parts" in content:
            for part in content["parts"]:
                if "text" in part and part["text"]:
                    accumulated_text = part["text"]
                    
    if not accumulated_text:
        print("Error: No response received from the agent pipeline.", file=sys.stderr)
        sys.exit(1)
        
    try:
        response_json = json.loads(accumulated_text)
    except json.JSONDecodeError as e:
        print(f"Error: Pipeline response was not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
        
    # Check if ui_available is True
    ui_available = response_json.get("ui_available", False)
    
    if ui_available:
        print("\n[UI IS AVAILABLE] Ignoring 'data' block entirely to isolate UI concerns...")
        ui_payload = response_json.get("ui", {})
        update_components = ui_payload.get("updateComponents", {})
        
        # Render the dashboard elements
        render_a2ui_dashboard(update_components)
    else:
        print("\n[UI NOT AVAILABLE] Falling back to text output since UI payload was not returned.")
        data_payload = response_json.get("data", {})
        print(f"Raw Output: {data_payload.get('raw_output', '')}")

if __name__ == "__main__":
    default_prompt = "Verify the user authentication module for any code flaws, inspect the requirements context, and run a safe test script in the sandbox."
    query_prompt = sys.argv[1] if len(sys.argv) > 1 else default_prompt
    run_canvas_ui(query_prompt)
