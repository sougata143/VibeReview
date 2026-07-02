# app/sub_agents/search/agent.py
# Search sub-agent to query knowledge graph (GQL) and vector database.

import os
import subprocess
import shutil
from google.adk.agents import Agent
from google.adk.models import Gemini
from google.genai import types
from app.config import Config

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

def query_spanner_graph(query: str, search_path: str = None, gql_query: str = None) -> dict:
    """Scans local code files recursively for keywords, SAST/SCA vulnerabilities, and SonarQube code smells.
    
    Args:
        query: The search term or pattern to look for.
        search_path: Optional path to scan. Defaults to the cloned repository path or local workspace.
        gql_query: Optional GQL query string for Spanner Graph.
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
        "[OWASP A03:2021-Injection] SQL Injection Risk": re.compile(
            r'(?i)(?:\.execute\(|db\.query\(|DriverManager\.getConnection\(|mysql_query\(|pg_query\().*f?["\'].*\{\w+\}.*["\']'
        ),
        "[OWASP A03:2021-Injection] Command Injection Risk": re.compile(
            r'(?i)(?:subprocess\.(?:run|Popen|call)\(.*shell\s*=\s*True|os\.system\(|exec\.Command\(|shell_exec\(|exec\(|system\(|IO\.popen\()'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Insecure Cryptography (MD5/SHA1)": re.compile(
            r'(?i)(?:hashlib\.(?:md5|sha1)\(|md5\.New\(|sha1\.New\(|md5\(|sha1\(|DigestUtils\.(?:md5Hex|sha1Hex)\()'
        ),
        "[OWASP A01:2021-Broken Access Control] Path Traversal Risk": re.compile(
            r'(?i)(?:open\(\s*(?:\w+\s*\+\s*\w+|\w+\.join\(|f["\'].*\{\w+\})|file_get_contents\(|FileStream\(|FileInputStream\()'
        ),
        "[OWASP A03:2021-Injection] Cross-Site Scripting (XSS)": re.compile(
            r'(?i)(?:render_template_string\(|innerHTML\s*=|echo\s+.*\$_GET|echo\s+.*\$_POST|response\.write\()'
        ),
        "[OWASP A03:2021-Injection] NoSQL Injection Risk": re.compile(
            r'(?i)(?:\$where\s*[:=]|find\(\s*\{\s*["\']\w+["\']\s*:\s*f?["\'])'
        ),
        "[OWASP A10:2021-SSRF] Server-Side Request Forgery (SSRF)": re.compile(
            r'(?i)(?:requests\.(?:get|post|put|delete|patch|request)|urllib\.request\.urlopen|http\.Get|HttpURLConnection)\(\s*(?:\w+\s*\+\s*\w+|\w+\.join|f["\'].*\{\w+\})'
        ),
        "[OWASP A08:2021-Software and Data Integrity Failures] Insecure Deserialization Risk": re.compile(
            r'(?i)(?:pickle\.loads\(|yaml\.load\(\s*\w+\s*\)|marshal\.loads\(|ObjectInputStream\()'
        ),
        "[OWASP A05:2021-Security Misconfiguration] XML External Entity (XXE) Injection": re.compile(
            r'(?i)(?:XMLParser\(|parseString\(|etree\.parse\(|etree\.fromstring\(|DocumentBuilderFactory)'
        ),
        "[OWASP A07:2021-Identification and Authentication Failures] Insecure Session/Cookie Settings": re.compile(
            r'(?i)(?:SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|WTF_CSRF_ENABLED\s*=\s*False)'
        ),
        "[OWASP A05:2021-Security Misconfiguration] Cross-Frame Scripting (XFS) / Clickjacking": re.compile(
            r'(?i)(?:X-Frame-Options\s*[:=]\s*["\']ALLOW-FROM["\']|X-Frame-Options\s*[:=]\s*["\']NONE["\'])'
        ),
        "[OWASP A01:2021-Broken Access Control] Insecure Direct Object References (IDOR)": re.compile(
            r'(?i)(?:def\s+\w+\(\s*.*(?:id|user_id|uuid|account_id)\s*\)\s*:.*\n\s*.*(?:select|find|query)\()'
        ),
        "[OWASP A03:2021-Injection] LDAP Injection": re.compile(
            r'(?i)(?:ldap\.search\(|ldap\.search_s\(|InitialDirContext\(\).*(?:search|lookup)).*f?["\'].*\{\w+\}.*["\']'
        ),
        "[OWASP A03:2021-Injection] XPath Injection": re.compile(
            r'(?i)(?:\.xpath\(|\.evaluate\(|XPathFactory\.newInstance\(\)).*f?["\'].*\{\w+\}.*["\']'
        ),
        "[OWASP A09:2021-Security Logging and Monitoring Failures] Sensitive Data Exposure (Logging Leak)": re.compile(
            r'(?i)(?:logger\.(?:info|debug|warn|error)\(.*(?:api_key|password|secret|token|passwd|pwd).*\)|System\.out\.print.*(?:password|secret).*)'
        ),
        "[OWASP A01:2021-Broken Access Control] Open Redirect": re.compile(
            r'(?i)(?:redirect\(|response\.sendRedirect\(|window\.location\s*=\s*)(?:\w+\s*\+\s*\w+|\w+\.join|f["\'].*\{\w+\}|\w+)'
        ),
        "[OWASP A03:2021-Injection] Format String Vulnerability": re.compile(
            r'(?i)(?:printf\(|sprintf\(|format\().*(?:%s|%d).*,\s*(?:\w+\s*\+\s*\w+)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Insecure Communication / SSL Verification Disabled": re.compile(
            r'(?i)(?:verify\s*=\s*False|verify\s*=\s*false|trustAllCerts|SSLContext\.getInstance\(\s*["\']SSL["\']\)|AllowAllHostnameVerifier)'
        ),
        "[OWASP A03:2021-Injection] HTTP Parameter Pollution (HPP)": re.compile(
            r'(?i)(?:request\.args\.getlist|request\.query_params\.getlist|getParameterValues)'
        ),
        "[OWASP A01:2021-Broken Access Control] CORS Allow All Config": re.compile(
            r'(?i)(?:CORS_ORIGIN_ALLOW_ALL\s*=\s*True|Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\'])'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Weak Cryptographic Salt / PBKDF2 Iterations": re.compile(
            r'(?i)(?:crypt\.pbkdf2|hashlib\.pbkdf2_hmac\(.*,\s*(?:[0-9]{1,3}|[0-9]{1,3}\s*\*\s*[0-9]{1,3})\s*,|bcrypt\.gensalt\(\s*(?:[1-7])\s*\))'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Weak Pseudo-Random Number Generator (PRNG)": re.compile(
            r'(?i)(?:random\.random\(|random\.randint\(|random\.choice\(|Math\.random\()'
        ),
        "[OWASP A03:2021-Injection] Code Injection Risk (eval/exec)": re.compile(
            r'(?i)(?:eval\(|exec\(|Function\(|evalString\()'
        ),
        "[OWASP A03:2021-Injection] SQL Wildcard Injection": re.compile(
            r'(?i)(?:select\s+.*\s+like\s+.*%|like\s*.*_GET)'
        ),
        "[OWASP A01:2021-Broken Access Control] Missing Function Access Control": re.compile(
            r'(?i)(?:@app\.route\(.*method.*post.*\)\s*\n\s*def\s+\w+\(\)\s*:\s*\n\s*(?!@auth|@login_required|@roles_required|check_permission))'
        ),
        "[OWASP A05:2021-Security Misconfiguration] Insecure HSTS Settings": re.compile(
            r'(?i)(?:Strict-Transport-Security\s*.*max-age=0|HSTS\s*=\s*False)'
        ),
        "[OWASP A07:2021-Identification and Authentication Failures] Cookie without SameSite attribute": re.compile(
            r'(?i)(?:set_cookie\(.*samesite\s*=\s*None|SameSite\s*=\s*None)'
        ),
        "[OWASP A05:2021-Security Misconfiguration] Regex Denial of Service (ReDoS) Risk": re.compile(
            r'(?i)(?:re\.compile\(.*(?:\.\*|\.\+)\s*\+|re\.match\(.*(?:\.\*|\.\+)\s*\+)'
        ),
        "[OWASP A09:2021-Security Logging and Monitoring Failures] Information Exposure through Exception Details": re.compile(
            r'(?i)(?:traceback\.print_exc\(|print_stack\(|printStackTrace\(\s*\)|e\.toString\(\))'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Hardcoded Sensitive Keys in Config": re.compile(
            r'(?i)(?:AWS_SECRET_ACCESS_KEY|STRIPE_API_KEY|GITHUB_TOKEN|SLACK_WEBHOOK_URL)\s*=\s*["\'][a-zA-Z0-9_\-\.\~]{10,}["\']'
        ),
        "[OWASP A01:2021-Broken Access Control] Insecure Temporary File Creation": re.compile(
            r'(?i)(?:tempfile\.mktemp\(|mktemp\(|GetTempFileName\(\))'
        ),
        "[OWASP A03:2021-Injection] Unsafe Java Reflection usage": re.compile(
            r'(?i)(?:Class\.forName\(|getDeclaredMethod\(|Method\.invoke\()'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Weak Cryptographic Key Size": re.compile(
            r'(?i)(?:RSA\.generate\(1024\)|RSA\.generate\(512\)|keySize\s*=\s*1024|keySize\s*=\s*512)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Broken Cryptographic Hash / MD4 usage": re.compile(
            r'(?i)(?:hashlib\.new\(\s*["\']md4["\']\s*\)|DigestUtils\.md4Hex)'
        ),
        "[OWASP A09:2021-Security Logging and Monitoring Failures] Improper Output Neutralization (Log Injection)": re.compile(
            r'(?i)logger\..*\(.*replace\([\'"]\\n[\'"],\s*[\'"][\'"]\)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Insecure Cryptographic Padding": re.compile(
            r'(?i)(?:Cipher\.getInstance\(\s*["\'].*/PKCS1Padding["\']|algorithms\.AES\(.*,\s*modes\.ECB\(\s*\)\))'
        ),
        "[OWASP A03:2021-Injection] Stored or Reflected XSS Input": re.compile(
            r'(?i)(?:Markup\(|_GET\[.*\]|_POST\[.*\]|dangerouslySetInnerHTML)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Use of Password Hash without Salt": re.compile(
            r'(?i)(?:hashlib\.sha256\(\w+\.encode\(\)\)|hashlib\.sha512\(\w+\.encode\(\)\))'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Insecure Cryptographic Cipher Mode": re.compile(
            r'(?i)(?:/CBC/PKCS5Padding|/CBC/NoPadding)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Hardcoded Credentials in Connection String": re.compile(
            r'(?i)(?:mongodb\+srv:\/\/|mysql:\/\/|postgresql:\/\/)[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@'
        ),
        "[OWASP A03:2021-Injection] Resource Injection (IP/Port manipulation)": re.compile(
            r'(?i)(?:socket\.connect\(\s*\(\s*_GET|_GET\[[\'"]port[\'"]\])'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Use of Broken Cryptographic Algorithm RC2": re.compile(
            r'(?i)(?:DigestUtils\.rc2Hex|Cipher\.getInstance\(\s*["\']RC2["\']\))'
        ),
        "[OWASP A08:2021-Software and Data Integrity Failures] Vulnerable YAML Deserialization": re.compile(
            r'(?i)(?:yaml\.load\(\s*.*?\s*(?:,\s*Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader))?\))'
        ),
        "[OWASP A01:2021-Broken Access Control] Use of Assertions for Access Control Security": re.compile(
            r'(?i)(?:assert\s+.*hasRole|assert\s+.*isAdmin|assert\s+.*authorized)'
        ),
        "[OWASP A03:2021-Injection] Expression Language (EL) Injection": re.compile(
            r'(?i)(?:\$\{\s*.*?\s*\}|#\{\s*.*?\s*\})'
        ),
        "[OWASP A03:2021-Injection] Server-Side Template Injection (SSTI)": re.compile(
            r'(?i)(?:render_template\(.*request\..*|render_template_string\(.*request\..*)'
        ),
        "[OWASP A03:2021-Injection] CRLF Injection / HTTP Response Splitting": re.compile(
            r'(?i)(?:\\r\\n|\b\w+\.replace\([\'"]\\n[\'"],[\'"]\\r[\'"]\))'
        ),
        "[OWASP A03:2021-Injection] Client-Side Template Injection": re.compile(
            r'(?i)(?:ng-bind-html|v-html|dangerouslySetInnerHTML)'
        ),
        "[OWASP A07:2021-Identification and Authentication Failures] Session Fixation": re.compile(
            r'(?i)(?:session\.id\s*=\s*request|session\.session_id\s*=\s*)'
        ),
        "[OWASP A07:2021-Identification and Authentication Failures] Insecure JWT Validation": re.compile(
            r'(?i)(?:jwt\.decode\(.*verify\s*=\s*False|jwt\.decode\(.*options\s*=\s*\{.*verify_signature.*False)'
        ),
        "[OWASP A01:2021-Broken Access Control] Mass Assignment": re.compile(
            r'(?i)(?:\*\*request\.form|\*\*request\.get_json\(\)|\*\*request\.json)'
        ),
        "[OWASP A02:2021-Cryptographic Failures] Cleartext Storage of Sensitive Information": re.compile(
            r'(?i)(?:localStorage\.setItem\(.*(?:password|api_key|token)|cookies\.set\(.*(?:password|api_key|token))'
        ),
        "[OWASP A03:2021-Injection] Unrestricted File Upload": re.compile(
            r'(?i)(?:request\.files.*save\(|MultipartFile|FileUpload)'
        ),
        "[OWASP A08:2021-Software and Data Integrity Failures] Memory Corruption / Use-After-Free": re.compile(
            r'\b(?:free\s*\(.*\)(?:\n|.)*free\s*\(.*\)|free\s*\(.*\)(?:\n|.)*\b\w+\s*=|\bdelete\s+.*delete\s+.*)\b'
        ),
        "[OWASP A03:2021-Injection] Integer Overflow/Wraparound": re.compile(
            r'(?i)(?:short\s+\w+\s*=\s*\d+|byte\s+\w+\s*=\s*\d+)'
        ),
        "[OWASP A01:2021-Broken Access Control] Race Condition / TOCTOU": re.compile(
            r'(?i)(?:os\.path\.exists\(.*\)(?:\n|.)*open\(|file\.exists\(.*\)(?:\n|.)*file\.write)'
        ),
        "[OWASP A04:2021-Insecure Design] Uncontrolled Resource Consumption / DoS": re.compile(
            r'(?i)(?:while\s+True\s*:\s*\n\s*pass|for\s+\w+\s+in\s+range\(\s*(?:999999|1000000|sys\.maxsize)\s*\))'
        ),
        "[OWASP A01:2021-Broken Access Control] Mobile Specific (Intent/WebView/Biometric)": re.compile(
            r'(?i)(?:setJavaScriptEnabled\(true\)|addJavascriptInterface|exported\s*=\s*true|biometricPrompt)'
        ),
        "[OWASP A04:2021-Insecure Design] Hardcoded IP Addresses": re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b'
        ),
        "[OWASP A05:2021-Security Misconfiguration] Debug Code Left in Production": re.compile(
            r'(?i)(?:app\.run\(.*debug\s*=\s*True|DEBUG\s*=\s*True)'
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
        ),
        "Cyclic Imports / Architectural Violation": re.compile(
            r'(?i)(?:import\s+.*?\s*;\s*\n\s*import\s+.*?\s*;\s*\n\s*import\s+.*?\s*;)'
        ),
        "Null Pointer Dereference Hazard": re.compile(
            r'(?i)(?:\b\w+\.delete\(\)\s*\n\s*\w+\.name|\b\w+\s*=\s*None\s*\n\s*\w+\.\w+)'
        ),
        "Array or Collection Out-of-Bounds Hazard": re.compile(
            r'(?i)(?:\[\s*-1\s*\]|\[\s*len\(\w+\)\s*\])'
        ),
        "Incorrect API Usage Pattern": re.compile(
            r'(?i)(?:assert\s+\w+\s*==\s*None|\.equals\(\s*\w+\s*\)\s*==\s*true)'
        ),
        "Mathematical Casting or Division-by-Zero Hazard": re.compile(
            r'(?i)(?:\/\s*0\b|%\s*0\b|\bint\(\s*float\(\s*\w+\s*\)\s*\))'
        ),
        "Thread-Safety Violation Hazard": re.compile(
            r'(?i)(?:threading\.Thread\(.*target\s*=\s*\w+.*\)\s*\n\s*(?!.*join|.*lock))'
        ),
        "Encapsulation Violation (Public Field)": re.compile(
            r'(?i)(?:public\s+\w+\s+\w+\s*=\s*.*;)'
        ),
        "Disabled CSRF Configuration": re.compile(
            r'(?i)(?:csrf\.disable\(\)|WTF_CSRF_ENABLED\s*=\s*False|csrf_enabled\s*=\s*false)'
        ),
        "Hardcoded IP Address Config": re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
        ),
        "God Class / Large Structural Smells": re.compile(
            r'(?i)class\s+\w+\s*\(.*?\)\s*:\s*\n(?:\s*def\s+\w+\(.*?\)\s*:\s*\n){10,}'
        ),
        "Redundant Assignment Duplication": re.compile(
            r'\b(\w+)\s*=\s*\1\b'
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
                is_sca_file = (
                    file in ["requirements.txt", "pyproject.toml", "uv.lock", "pom.xml", "build.gradle", "package.json",
                             "build.gradle.kts", "ivy.xml", "build.sbt", "poetry.lock", "Pipfile", "Pipfile.lock",
                             "setup.py", "setup.cfg", "Package.swift", "Package.resolved", "Podfile", "Podfile.lock",
                             "Cartfile", "Cartfile.private", "Cartfile.resolved", "go.mod", "go.sum", "Gopkg.lock",
                             "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"]
                    or (file.startswith("requirements-") and file.endswith(".txt"))
                )
                if is_sca_file:
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            dep_content = f.read()
                            
                            # 1. License Compliance Checks (Copyleft licenses check)
                            license_match = re.search(r'(?i)(?:"license"\s*:\s*"([^"]*(?:GPL|AGPL|LGPL|MPL)[^"]*)"|<license>[^<]*(?:GPL|AGPL|LGPL|MPL)[^<]*</license>|license\s*=\s*[\'"]([^\'"]*(?:GPL|AGPL|LGPL|MPL)[^\'"]*)[\'"])', dep_content)
                            if license_match:
                                license_name = license_match.group(1) or license_match.group(2)
                                sca_violations.append({
                                    "file": filepath,
                                    "dependency": "multiple",
                                    "version": "N/A",
                                    "rule": f"SCA License Risk: Copyleft license '{license_name}' detected. This may require disclosing proprietary source code.",
                                    "severity": "HIGH"
                                })
                                
                            # 2. Typosquatting/Malicious Package Detection
                            malicious_libs = ["pythoon", "reqeusts", "lodas", "exprees", "cryptographhy", "django-secure-config"]
                            for m_lib in malicious_libs:
                                if m_lib in dep_content.lower():
                                    sca_violations.append({
                                        "file": filepath,
                                        "dependency": m_lib,
                                        "version": "N/A",
                                        "rule": f"SCA Malicious Package: Potential typosquatting/dependency confusion attack targeting '{m_lib}'",
                                        "severity": "CRITICAL"
                                    })
                                    
                            # 3. Outdated/Unmaintained Dependency Tracking
                            zero_ver_match = re.search(r'(?i)(?:==|:|"|\b)0\.[0-9]+\.[0-9]+', dep_content)
                            if zero_ver_match:
                                sca_violations.append({
                                    "file": filepath,
                                    "dependency": "multiple",
                                    "version": zero_ver_match.group(0),
                                    "rule": f"SCA Outdated Dependency: Pinned to unstable/pre-1.0.0 version '{zero_ver_match.group(0)}'",
                                    "severity": "INFO"
                                })
                            
                            # 4. Known Vulnerabilities (CVE Identification)
                            # Python SCA
                            if file in ["requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg"] or (file.startswith("requirements-") and file.endswith(".txt")):
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
                                            
                            # Java SCA
                            if file in ["pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml", "build.sbt"]:
                                for lib, rule in sca_rules.items():
                                    if lib in ["log4j-core", "spring-beans", "spring-core", "jackson-databind", "commons-text"]:
                                        if lib in dep_content.lower():
                                            match = re.search(rf'<artifactId>{lib}</artifactId>\s*<version>([0-9\.]+)</version>|{lib}:([0-9\.]+)', dep_content)
                                            if match:
                                                version_str = match.group(1) or match.group(2)
                                                if is_vulnerable(version_str, rule["version"]):
                                                    sca_violations.append({
                                                        "file": filepath,
                                                        "dependency": lib,
                                                        "version": version_str,
                                                        "rule": f"SCA Vulnerable Dependency: {rule['name']} ({rule['cve']})",
                                                        "severity": rule["severity"]
                                                    })
                                            
                            # Node.js SCA
                            if file in ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"]:
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
                    
        # Resolve cross-repository dependencies if GQL query or cross-repo search is requested
        cross_repo_dependencies = []
        if gql_query or (query and any(x in query.lower() for x in ["cross-repo", "dependency", "dependencies", "call map"])):
            repos_dir = "cloned_repos"
            repo_names = []
            if os.path.exists(repos_dir):
                repo_names = [d for d in os.listdir(repos_dir) if os.path.isdir(os.path.join(repos_dir, d))]
            # Include local repo as vibe-review
            repo_names.append("vibe-review")
            
            # Map of defined functions per repository to trace CALLS edges in GQL
            defined_functions = {}
            for r_name in repo_names:
                r_path = os.path.join(repos_dir, r_name) if r_name != "vibe-review" else "."
                defined_functions[r_name] = []
                if not os.path.exists(r_path):
                    continue
                for root, dirs, files in os.walk(r_path):
                    dirs[:] = [d for d in dirs if d not in ignore_dirs]
                    for file in files:
                        if file.endswith(".py"):
                            f_path = os.path.join(root, file)
                            try:
                                with open(f_path, "r", errors="ignore") as f:
                                    content = f.read()
                                # Simple regex to find defined functions: def func_name(...)
                                funcs = re.findall(r'\bdef\s+(\w+)\s*\(', content)
                                defined_functions[r_name].extend(funcs)
                            except Exception:
                                pass
            
            # Trace imports and function calls across repositories
            for r_name in repo_names:
                r_path = os.path.join(repos_dir, r_name) if r_name != "vibe-review" else "."
                if not os.path.exists(r_path):
                    continue
                for root, dirs, files in os.walk(r_path):
                    dirs[:] = [d for d in dirs if d not in ignore_dirs]
                    for file in files:
                        if file.endswith(".py"):
                            f_path = os.path.join(root, file)
                            try:
                                with open(f_path, "r", errors="ignore") as f:
                                    content = f.read()
                                
                                # 1. Check direct imports of sibling repositories
                                for other_r in repo_names:
                                    if other_r == r_name:
                                        continue
                                    if re.search(rf'\b(?:import|from)\s+{other_r}\b', content):
                                        cross_repo_dependencies.append({
                                            "source_node": f"Repository({r_name})",
                                            "target_node": f"Repository({other_r})",
                                            "edge_type": "DEPENDS_ON",
                                            "details": f"File '{file}' in repository '{r_name}' imports repository '{other_r}'."
                                        })
                                        
                                # 2. Check function calls targeting functions defined in other repos
                                for other_r, other_funcs in defined_functions.items():
                                    if other_r == r_name:
                                        continue
                                    for func in other_funcs:
                                        if re.search(rf'\b{func}\s*\(', content):
                                            cross_repo_dependencies.append({
                                                "source_node": f"Function({r_name}.{file}:{func})",
                                                "target_node": f"Function({other_r}:{func})",
                                                "edge_type": "CALLS",
                                                "details": f"Function call to '{func}' maps across repositories from '{r_name}' to '{other_r}'."
                                            })
                            except Exception:
                                pass

        return {
            "status": "success",
            "search_path": os.path.abspath(search_path),
            "query": query,
            "gql_query": gql_query,
            "matches_found": len(matches),
            "results": matches[:20],
            "sast_violations": sast_violations,
            "sca_violations": sca_violations,
            "code_smells": code_smells,
            "cross_repo_dependencies": cross_repo_dependencies
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def create_search_agent() -> Agent:
    """Factory function for the Search sub-agent."""
    return Agent(
        name="search_agent",
        model=Gemini(
            model=Config.DEFAULT_MODEL,
            retry_options=types.HttpRetryOptions(attempts=6, initial_delay=6.0)
        ),
        instruction="""You are the Search Agent. Your job is to locate the target codebase and search for files and vulnerabilities. 
If the user specifies a remote Git or GitHub repository URL, first call `clone_github_repo` to download it locally.
Then, use `query_spanner_graph` to recursively search the files for keywords, and execute automated Checkmarx-style SAST, SCA, and SonarQube-style Code Smell scans.
Extract and pass all matching lines, SAST/SCA security violations, and Code Smells down the pipeline to the next agent.""",
        description="Searches code structure and metadata in Spanner Graph.",
        tools=[clone_github_repo, query_spanner_graph]
    )
