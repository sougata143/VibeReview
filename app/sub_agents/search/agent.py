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
    """Scans local code files recursively for keywords, SAST/SCA vulnerabilities, and SonarQube code smells.
    
    Args:
        query: The search term or pattern to look for.
        search_path: Optional path to scan. Defaults to the cloned repository path or local workspace.
    """
    import re
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
    sast_violations = []
    sca_violations = []
    code_smells = []
    
    query_lower = query.lower()
    
    ignore_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", ".google-agents-cli", "node_modules"}
    ignore_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf", ".pyc", ".db", ".lock"}
    
    # Multi-Language SAST Patterns (Python, JavaScript/TypeScript, Go, PHP, Java, Ruby, C/C++)
    sast_patterns = {
        "SQL Injection Risk": re.compile(
            r'(?i)(?:\.execute\(|db\.query\(|DriverManager\.getConnection\(|mysql_query\(|pg_query\().*f?["\'].*\{\w+\}.*["\']'
        ),
        "Command Injection Risk": re.compile(
            r'(?i)(?:subprocess\.(?:run|Popen|call)\(.*shell\s*=\s*True|os\.system\(|exec\.Command\(|shell_exec\(|exec\(|system\(|IO\.popen\()'
        ),
        "Insecure Cryptography (MD5/SHA1)": re.compile(
            r'(?i)(?:hashlib\.(?:md5|sha1)\(|md5\.New\(|sha1\.New\(|md5\(|sha1\(|DigestUtils\.(?:md5Hex|sha1Hex)\()'
        ),
        "Path Traversal Risk": re.compile(
            r'(?i)(?:open\(\s*(?:\w+\s*\+\s*\w+|\w+\.join\(|f["\'].*\{\w+\})|file_get_contents\(|FileStream\(|FileInputStream\()'
        ),
        "Cross-Site Scripting (XSS)": re.compile(
            r'(?i)(?:render_template_string\(|innerHTML\s*=|echo\s+.*\$_GET|echo\s+.*\$_POST|response\.write\()'
        )
    }
    
    # Multi-Language SonarQube Code Smell Patterns
    smell_patterns = {
        "Empty Exception Handler": re.compile(
            r'(?i)(?:except\s*:\s*\n\s*pass|except\s+Exception\s*:\s*\n?\s*pass|catch\s*\(\s*\w+\s*\)\s*\{\s*\}|catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\})'
        ),
        "Hardcoded Credential / Secret": re.compile(
            r'(?i)(?:api_key|password|secret|token|passcode|private_key)\s*=\s*["\'][a-zA-Z0-9_\-\.\~]{8,}["\']'
        ),
        "Leftover TODO/FIXME Comment": re.compile(
            r'(?i)(?:#|//|/\*)\s*(?:todo|fixme)'
        ),
        "Broad Catch Block": re.compile(
            r'(?i)(?:except\s+Exception|catch\s*\(\s*Exception|catch\s*\(\s*Throwable)'
        )
    }
    
    # SCA Insecure Versions
    sca_insecure = {
        "pyjwt": "<2.4.0",
        "requests": "<2.31.0",
        "flask": "<2.0.0",
        "django": "<4.0.0",
        "cryptography": "<39.0.0"
    }
    
    try:
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ignore_extensions:
                    continue
                    
                filepath = os.path.join(root, file)
                
                # Check for SCA in dependency config files
                if file in ["requirements.txt", "pyproject.toml", "uv.lock"]:
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            dep_content = f.read()
                            for lib, constraint in sca_insecure.items():
                                if lib in dep_content.lower():
                                    match = re.search(rf'(?i){lib}==([0-9\.]+)', dep_content)
                                    if match:
                                        version_str = match.group(1)
                                        v_parts = [int(p) for p in version_str.split('.') if p.isdigit()]
                                        if lib == "pyjwt" and len(v_parts) >= 2 and (v_parts[0] < 2 or (v_parts[0] == 2 and v_parts[1] < 4)):
                                            sca_violations.append({
                                                "file": filepath,
                                                "dependency": lib,
                                                "version": version_str,
                                                "rule": "SCA Outdated Dependency (CVE-2022-29217 Risk)",
                                                "severity": "CRITICAL"
                                            })
                                        elif lib == "requests" and len(v_parts) >= 2 and (v_parts[0] < 2 or (v_parts[0] == 2 and v_parts[1] < 31)):
                                            sca_violations.append({
                                                "file": filepath,
                                                "dependency": lib,
                                                "version": version_str,
                                                "rule": "SCA Vulnerable Dependency (Insecure requests version)",
                                                "severity": "HIGH"
                                            })
                    except Exception:
                        pass
                
                # Scan source files for SAST and Code Smells
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
                            
                            for vuln_type, pattern in sast_patterns.items():
                                if pattern.search(line):
                                    sast_violations.append({
                                        "file": filepath,
                                        "line": line_idx + 1,
                                        "rule": vuln_type,
                                        "content": line.strip(),
                                        "severity": "HIGH"
                                    })
                                    
                            for smell_type, pattern in smell_patterns.items():
                                if pattern.search(line):
                                    code_smells.append({
                                        "file": filepath,
                                        "line": line_idx + 1,
                                        "rule": smell_type,
                                        "content": line.strip(),
                                        "severity": "INFO"
                                    })
                except Exception:
                    continue
                    
        return {
            "status": "success",
            "search_path": os.path.abspath(search_path),
            "query": query,
            "matches_found": len(matches),
            "results": matches[:20],
            "sast_violations": sast_violations,
            "sca_violations": sca_violations,
            "code_smells": code_smells
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
Then, use `query_spanner_graph` to recursively search the files for keywords, and execute automated Checkmarx-style SAST, SCA, and SonarQube-style Code Smell scans.
Extract and pass all matching lines, SAST/SCA security violations, and Code Smells down the pipeline to the next agent.""",
        description="Searches code structure and metadata in Spanner Graph.",
        tools=[clone_github_repo, query_spanner_graph]
    )
