# app/sub_agents/search/agent.py
# Search sub-agent to query knowledge graph (GQL) and vector database.

import os
import subprocess
import shutil
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types

def clone_github_repo(repo_url: str, local_path: str = "cloned_repos/demo_repo") -> dict:
    """Clones a remote GitHub repository to a local directory for scanning.
    
    Args:
        repo_url: The https or git URL of the GitHub repository.
        local_path: The local directory path to clone the repository to.
    """
    try:
        # Ensure the parent directory exists
        parent_dir = os.path.dirname(local_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        
        # If target directory already exists, pull or remove and re-clone
        if os.path.exists(local_path):
            if os.path.exists(os.path.join(local_path, ".git")):
                res = subprocess.run(
                    ["git", "pull"],
                    cwd=local_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if res.returncode == 0:
                    return {
                        "status": "success",
                        "message": f"Repository already exists at {local_path}. Updated via git pull successfully."
                    }
            
            # Otherwise, delete and re-clone
            shutil.rmtree(local_path)
        
        # Run clone
        res = subprocess.run(
            ["git", "clone", repo_url, local_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        if res.returncode == 0:
            return {
                "status": "success",
                "message": f"Successfully cloned repository {repo_url} to {local_path}."
            }
        else:
            return {
                "status": "failed",
                "error": res.stderr or "Unknown git clone error"
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def query_spanner_graph(query: str, search_path: str = None) -> dict:
    """Scans local code files recursively to search for keywords or potential vulnerabilities.
    
    Args:
        query: The search term or pattern to look for (e.g. 'auth', 'JWT', 'hash').
        search_path: Optional path to scan. Defaults to the cloned repository path or local workspace.
    """
    # Resolve search directory
    if not search_path:
        if os.path.exists("cloned_repos/demo_repo"):
            search_path = "cloned_repos/demo_repo"
        elif os.path.exists("vibe-review"):
            search_path = "vibe-review"
        else:
            search_path = "."
            
    if not os.path.exists(search_path):
        return {"status": "failed", "error": f"Search path {search_path} does not exist."}
        
    matches = []
    query_lower = query.lower()
    
    ignore_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", ".google-agents-cli", "node_modules"}
    ignore_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf", ".pyc", ".db", ".lock"}
    
    try:
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ignore_extensions:
                    continue
                    
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for line_idx, line in enumerate(lines):
                            if query_lower in line.lower():
                                matches.append({
                                    "file": filepath,
                                    "line": line_idx + 1,
                                    "content": line.strip()
                                })
                                if len(matches) >= 100:
                                    break
                except Exception:
                    continue
                    
                if len(matches) >= 100:
                    break
        
        return {
            "status": "success",
            "search_path": os.path.abspath(search_path),
            "query": query,
            "matches_found": len(matches),
            "results": matches[:20]
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def create_search_agent() -> Agent:
    """Factory function for the Search sub-agent."""
    return Agent(
        name="search_agent",
        model=Gemini(
            model="gemini-3.1-flash-lite",
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Search Agent. Your job is to locate the target codebase and search for files and vulnerabilities. 
If the user specifies a remote Git or GitHub repository URL, first call `clone_github_repo` to download it locally.
Then, use `query_spanner_graph` to recursively search the files for keywords, vulnerabilities, or components related to the user request.
Pass the paths of the files you find, their matching lines, and details down the pipeline to the next agent.""",
        description="Searches code structure and metadata in Spanner Graph.",
        tools=[clone_github_repo, query_spanner_graph]
    )
