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
        ),
        "NoSQL Injection Risk": re.compile(
            r'(?i)(?:\$where\s*[:=]|find\(\s*\{\s*["\']\w+["\']\s*:\s*f?["\'])'
        ),
        "Server-Side Request Forgery (SSRF)": re.compile(
            r'(?i)(?:requests\.(?:get|post|put|delete|patch|request)|urllib\.request\.urlopen|http\.Get|HttpURLConnection)\(\s*(?:\w+\s*\+\s*\w+|\w+\.join|f["\'].*\{\w+\})'
        ),
        "Insecure Deserialization Risk": re.compile(
            r'(?i)(?:pickle\.loads\(|yaml\.load\(\s*\w+\s*\)|marshal\.loads\(|ObjectInputStream\()'
        ),
        "XML External Entity (XXE) Injection": re.compile(
            r'(?i)(?:XMLParser\(|parseString\(|etree\.parse\(|etree\.fromstring\(|DocumentBuilderFactory)'
        ),
        "Insecure Session/Cookie Settings": re.compile(
            r'(?i)(?:SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|WTF_CSRF_ENABLED\s*=\s*False)'
        ),
        "Cross-Frame Scripting (XFS) / Clickjacking": re.compile(
            r'(?i)(?:X-Frame-Options\s*[:=]\s*["\']ALLOW-FROM["\']|X-Frame-Options\s*[:=]\s*["\']NONE["\'])'
        ),
        "Insecure Direct Object References (IDOR)": re.compile(
            r'(?i)(?:def\s+\w+\(\s*.*(?:id|user_id|uuid|account_id)\s*\)\s*:.*\n\s*.*(?:select|find|query)\()'
        ),
        "LDAP Injection": re.compile(
            r'(?i)(?:ldap\.search\(|ldap\.search_s\(|InitialDirContext\(\).*(?:search|lookup)).*f?["\'].*\{\w+\}.*["\']'
        ),
        "XPath Injection": re.compile(
            r'(?i)(?:\.xpath\(|\.evaluate\(|XPathFactory\.newInstance\(\)).*f?["\'].*\{\w+\}.*["\']'
        ),
        "Sensitive Data Exposure (Logging Leak)": re.compile(
            r'(?i)(?:logger\.(?:info|debug|warn|error)\(.*(?:api_key|password|secret|token|passwd|pwd).*\)|System\.out\.print.*(?:password|secret).*)'
        ),
        "Open Redirect": re.compile(
            r'(?i)(?:redirect\(|response\.sendRedirect\(|window\.location\s*=\s*)(?:\w+\s*\+\s*\w+|\w+\.join|f["\'].*\{\w+\}|\w+)'
        ),
        "Format String Vulnerability": re.compile(
            r'(?i)(?:printf\(|sprintf\(|format\().*(?:%s|%d).*,\s*(?:\w+\s*\+\s*\w+)'
        ),
        "Insecure Communication / SSL Verification Disabled": re.compile(
            r'(?i)(?:verify\s*=\s*False|verify\s*=\s*false|trustAllCerts|SSLContext\.getInstance\(\s*["\']SSL["\']\)|AllowAllHostnameVerifier)'
        ),
        "HTTP Parameter Pollution (HPP)": re.compile(
            r'(?i)(?:request\.args\.getlist|request\.query_params\.getlist|getParameterValues)'
        ),
        "CORS Allow All Config": re.compile(
            r'(?i)(?:CORS_ORIGIN_ALLOW_ALL\s*=\s*True|Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\'])'
        ),
        "Weak Cryptographic Salt / PBKDF2 Iterations": re.compile(
            r'(?i)(?:crypt\.pbkdf2|hashlib\.pbkdf2_hmac\(.*,\s*(?:[0-9]{1,3}|[0-9]{1,3}\s*\*\s*[0-9]{1,3})\s*,|bcrypt\.gensalt\(\s*(?:[1-7])\s*\))'
        ),
        "Weak Pseudo-Random Number Generator (PRNG)": re.compile(
            r'(?i)(?:random\.random\(|random\.randint\(|random\.choice\(|Math\.random\()'
        ),
        "Code Injection Risk (eval/exec)": re.compile(
            r'(?i)(?:eval\(|exec\(|Function\(|evalString\()'
        ),
        "SQL Wildcard Injection": re.compile(
            r'(?i)(?:select\s+.*\s+like\s+.*%|like\s*.*_GET)'
        ),
        "Missing Function Access Control": re.compile(
            r'(?i)(?:@app\.route\(.*method.*post.*\)\s*\n\s*def\s+\w+\(\)\s*:\s*\n\s*(?!@auth|@login_required|@roles_required|check_permission))'
        ),
        "Insecure HSTS Settings": re.compile(
            r'(?i)(?:Strict-Transport-Security\s*.*max-age=0|HSTS\s*=\s*False)'
        ),
        "Cookie without SameSite attribute": re.compile(
            r'(?i)(?:set_cookie\(.*samesite\s*=\s*None|SameSite\s*=\s*None)'
        ),
        "Regex Denial of Service (ReDoS) Risk": re.compile(
            r'(?i)(?:re\.compile\(.*(?:\.\*|\.\+)\s*\+|re\.match\(.*(?:\.\*|\.\+)\s*\+)'
        ),
        "Information Exposure through Exception Details": re.compile(
            r'(?i)(?:traceback\.print_exc\(|print_stack\(|printStackTrace\(\s*\)|e\.toString\(\))'
        ),
        "Hardcoded Sensitive Keys in Config": re.compile(
            r'(?i)(?:AWS_SECRET_ACCESS_KEY|STRIPE_API_KEY|GITHUB_TOKEN|SLACK_WEBHOOK_URL)\s*=\s*["\'][a-zA-Z0-9_\-\.\~]{10,}["\']'
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
        ),
        "Cognitive/Cyclomatic Complexity Smell": re.compile(
            r'(?i)(?:\s*if\s+.*:\s*\n\s*if\s+.*:\s*\n\s*if\s+.*:|\s*for\s+.*:\s*\n\s*for\s+.*:\s*\n\s*for\s+.*:)'
        ),
        "Long Parameter List": re.compile(
            r'(?i)def\s+\w+\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,'
        ),
        "Naming Convention Violation": re.compile(
            r'\b(?:foo|bar|baz|temp|tmp|var|val|data)\d*\s*=\s*'
        ),
        "Dead Code / Unused Local Variables": re.compile(
            r'(?i)#\s*def\s+\w+\(|#\s*class\s+\w+'
        ),
        "Duplicate Imports on One Line": re.compile(
            r'(?i)(?:import\s+\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+)'
        ),
        "Magic Number Usage": re.compile(
            r'(?i)(?:\* 86400|\* 3600|\* 1000|\* 60|\b3.1415926535\b)'
        ),
        "Suboptimal Comparison / Redundant Boolean": re.compile(
            r'(?i)(?:==\s*True|==\s*False|!=\s*True|!=\s*False|==\s*true|==\s*false)'
        ),
        "Empty Class or Method": re.compile(
            r'(?i)(?:def\s+\w+\(\s*.*?\)\s*:\s*\n\s*pass|class\s+\w+\s*:\s*\n\s*pass)'
        ),
        "System Exit in Code": re.compile(
            r'(?i)(?:sys\.exit\(|os\._exit\(|System\.exit\()'
        ),
        "Use of Deprecated APIs": re.compile(
            r'(?i)(?:urllib2|optparse|md5\.new|sha\.new)'
        )
    }
    
    # Extended SCA NVD / OWASP Dependency Mapping
    sca_rules = {
        "pyjwt": {"version": "<2.4.0", "cve": "CVE-2022-29217", "name": "PyJWT key confusion bypass", "severity": "CRITICAL"},
        "requests": {"version": "<2.31.0", "cve": "CVE-2023-32681", "name": "Requests Proxy-Authorization leak", "severity": "HIGH"},
        "django": {"version": "<4.0.7", "cve": "CVE-2022-34265", "name": "Django SQL Injection", "severity": "CRITICAL"},
        "flask": {"version": "<2.2.0", "cve": "CVE-2023-30861", "name": "Flask session signing evasion", "severity": "HIGH"},
        "cryptography": {"version": "<39.0.1", "cve": "CVE-2023-23931", "name": "Cryptography cipher bypass", "severity": "HIGH"},
        "urllib3": {"version": "<1.26.17", "cve": "CVE-2023-43804", "name": "urllib3 Proxy-Authorization leak", "severity": "HIGH"},
        "jinja2": {"version": "<3.1.3", "cve": "CVE-2024-22143", "name": "Jinja2 sandbox escape", "severity": "HIGH"},
        "lodash": {"version": "<4.17.21", "cve": "CVE-2020-8203", "name": "Lodash Prototype Pollution", "severity": "HIGH"},
        "express": {"version": "<4.19.2", "cve": "CVE-2024-43796", "name": "Express open redirect / path traversal", "severity": "HIGH"},
        "axios": {"version": "<1.6.0", "cve": "CVE-2023-45857", "name": "Axios SSRF header leak", "severity": "HIGH"},
        "jsonwebtoken": {"version": "<9.0.0", "cve": "CVE-2022-23540", "name": "jsonwebtoken signature validation bypass", "severity": "CRITICAL"},
        "mongoose": {"version": "<7.0.0", "cve": "CVE-2023-26117", "name": "Mongoose prototype pollution", "severity": "HIGH"},
        "semver": {"version": "<7.5.2", "cve": "CVE-2023-35116", "name": "Semver ReDoS vulnerability", "severity": "HIGH"},
        "log4j-core": {"version": "<2.17.0", "cve": "CVE-2021-44228", "name": "Log4Shell RCE", "severity": "CRITICAL"},
        "spring-beans": {"version": "<5.3.18", "cve": "CVE-2022-22965", "name": "Spring4Shell RCE", "severity": "CRITICAL"},
        "spring-core": {"version": "<5.3.18", "cve": "CVE-2022-22965", "name": "Spring4Shell RCE", "severity": "CRITICAL"},
        "jackson-databind": {"version": "<2.13.4", "cve": "CVE-2022-42003", "name": "Jackson-databind deserialization RCE", "severity": "CRITICAL"},
        "commons-text": {"version": "<1.10.0", "cve": "CVE-2022-42889", "name": "Text4Shell RCE", "severity": "CRITICAL"}
    }
    
    def is_vulnerable(version_str, target_version):
        try:
            v_parts = [int(p) for p in version_str.split('.') if p.isdigit()]
            t_parts = [int(p) for p in target_version.replace('<', '').split('.') if p.isdigit()]
            max_len = max(len(v_parts), len(t_parts))
            v_parts += [0] * (max_len - len(v_parts))
            t_parts += [0] * (max_len - len(t_parts))
            return v_parts < t_parts
        except Exception:
            return False
            
    try:
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ignore_extensions:
                    continue
                    
                filepath = os.path.join(root, file)
                
                # Check for SCA in dependency config files
                if file in ["requirements.txt", "pyproject.toml", "uv.lock", "pom.xml", "build.gradle", "package.json"]:
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            dep_content = f.read()
                            
                            # Python SCA (requirements.txt / pyproject.toml)
                            if file in ["requirements.txt", "pyproject.toml", "uv.lock"]:
                                for lib, rule in sca_rules.items():
                                    if lib in ["pyjwt", "requests", "django", "flask", "cryptography", "urllib3", "jinja2"]:
                                        if lib in dep_content.lower():
                                            match = re.search(rf'(?i){lib}==([0-9\.]+)', dep_content)
                                            if match:
                                                version_str = match.group(1)
                                                if is_vulnerable(version_str, rule["version"]):
                                                    sca_violations.append({
                                                        "file": filepath,
                                                        "dependency": lib,
                                                        "version": version_str,
                                                        "rule": f"SCA Vulnerable Dependency: {rule['name']} ({rule['cve']})",
                                                        "severity": rule["severity"]
                                                    })
                                            
                            # Java SCA (pom.xml)
                            if file == "pom.xml":
                                for lib, rule in sca_rules.items():
                                    if lib in ["log4j-core", "spring-beans", "spring-core", "jackson-databind", "commons-text"]:
                                        if lib in dep_content.lower():
                                            match = re.search(rf'<artifactId>{lib}</artifactId>\s*<version>([0-9\.]+)</version>', dep_content)
                                            if match:
                                                version_str = match.group(1)
                                                if is_vulnerable(version_str, rule["version"]):
                                                    sca_violations.append({
                                                        "file": filepath,
                                                        "dependency": lib,
                                                        "version": version_str,
                                                        "rule": f"SCA Vulnerable Dependency: {rule['name']} ({rule['cve']})",
                                                        "severity": rule["severity"]
                                                    })
                                            
                            # Gradle SCA (build.gradle)
                            if file == "build.gradle":
                                for lib, rule in sca_rules.items():
                                    if lib in ["log4j-core", "spring-beans", "spring-core", "jackson-databind", "commons-text"]:
                                        if lib in dep_content.lower():
                                            match = re.search(rf'{lib}:([0-9\.]+)', dep_content)
                                            if match:
                                                version_str = match.group(1)
                                                if is_vulnerable(version_str, rule["version"]):
                                                    sca_violations.append({
                                                        "file": filepath,
                                                        "dependency": lib,
                                                        "version": version_str,
                                                        "rule": f"SCA Vulnerable Dependency: {rule['name']} ({rule['cve']})",
                                                        "severity": rule["severity"]
                                                    })
                                            
                            # Node.js SCA (package.json)
                            if file == "package.json":
                                for lib, rule in sca_rules.items():
                                    if lib in ["lodash", "express", "axios", "jsonwebtoken", "mongoose", "semver"]:
                                        if lib in dep_content.lower():
                                            match = re.search(rf'"{lib}"\s*:\s*"[~\^]?([0-9\.]+)"', dep_content)
                                            if match:
                                                version_str = match.group(1)
                                                if is_vulnerable(version_str, rule["version"]):
                                                    sca_violations.append({
                                                        "file": filepath,
                                                        "dependency": lib,
                                                        "version": version_str,
                                                        "rule": f"SCA Vulnerable Dependency: {rule['name']} ({rule['cve']})",
                                                        "severity": rule["severity"]
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
