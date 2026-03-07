"""
sql_detector.py — Layer 1 Security: SQL Injection Detection Engine

WHY THIS FILE EXISTS:
Before any user input touches the database, we scan it here.
Think of this as a security guard at the front door.

HOW IT WORKS:
- We maintain a list of known SQL injection patterns (regex)
- Every input field is scanned against these patterns
- If a match is found → request is BLOCKED and LOGGED
- If clean → request proceeds to the database layer
"""

import re
import logging
from datetime import datetime

# Configure logging — all attacks are written to attack.log
logging.basicConfig(
    filename='attack.log',
    level=logging.WARNING,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# ============================================================
# MASTER LIST OF SQL INJECTION PATTERNS
# Each pattern targets a specific attack technique
# ============================================================
SQL_INJECTION_PATTERNS = [
    # 1. Classic auth bypass: ' OR '1'='1
    r"('|\")(\s)*(or|OR)(\s)*('|\")(\s)*\d",

    # 2. Comment-based injection: admin'-- or admin'#
    r"('|\")\s*(-{2}|#|\/\*)",

    # 3. UNION-based data extraction: UNION SELECT
    r"\b(UNION)\b(\s)*(ALL)?(\s)*(SELECT)\b",

    # 4. Stacked queries: ; DROP TABLE
    r";(\s)*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC)\b",

    # 5. Boolean-based blind injection: AND 1=1
    r"\b(AND|OR)\b(\s)+\d+(\s)*=(\s)*\d+",

    # 6. Time-based blind injection: SLEEP(5) or WAITFOR
    r"\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(",

    # 7. Subquery injection
    r"\bSELECT\b.+\bFROM\b",

    # 8. Hex encoding bypass: 0x61646d696e
    r"0x[0-9a-fA-F]+",

    # 9. String concatenation bypass: CHAR(65)||CHAR(68)
    r"\bCHAR\s*\(\s*\d+\s*\)",

    # 10. Information schema access: information_schema
    r"\b(information_schema|sys\.|mysql\.|pg_)\b",

    # 11. Function-based: LOAD_FILE, INTO OUTFILE
    r"\b(LOAD_FILE|INTO\s+(OUTFILE|DUMPFILE))\b",

    # 12. Error-based: EXTRACTVALUE, UPDATEXML
    r"\b(EXTRACTVALUE|UPDATEXML|EXP\(~)\b",

    # 13. Tautology: ' OR 1=1
    r"'\s*(OR|AND)\s*\d\s*=\s*\d",

    # 14. Null byte injection
    r"(%00|\\x00|\\0)",

    # 15. Multiple statements
    r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
]

# Compile all patterns for performance (done once at startup)
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS]


def detect_sql_injection(user_input: str, field_name: str = "unknown", ip: str = "unknown") -> dict:
    """
    Scan a single input string for SQL injection attempts.
    
    Args:
        user_input: The raw string from the user (form field, URL param, etc.)
        field_name: Which field this came from (for logging)
        ip: The requester's IP address (for logging)
    
    Returns:
        {
            "is_safe": True/False,
            "threat_level": "none" / "low" / "high" / "critical",
            "matched_pattern": "..." or None,
            "message": human-readable result
        }
    """
    if not user_input or not isinstance(user_input, str):
        return {"is_safe": True, "threat_level": "none", "matched_pattern": None, "message": "Input is empty or non-string"}

    # Check each compiled pattern
    for i, pattern in enumerate(COMPILED_PATTERNS):
        match = pattern.search(user_input)
        if match:
            # Determine severity based on pattern index
            if i in [3, 6, 10, 11]:   # DROP/SELECT/LOAD_FILE — critical
                threat_level = "critical"
            elif i in [2, 4, 14]:      # UNION/Boolean/Null byte — high
                threat_level = "high"
            else:
                threat_level = "medium"

            # Log the attack attempt
            log_message = (
                f"SQLi DETECTED | IP={ip} | Field={field_name} | "
                f"Level={threat_level} | Pattern={i+1} | "
                f"Input='{user_input[:100]}'"  # Log only first 100 chars
            )
            logging.warning(log_message)

            return {
                "is_safe": False,
                "threat_level": threat_level,
                "matched_pattern": SQL_INJECTION_PATTERNS[i],
                "message": f"SQL injection detected in field '{field_name}'",
                "pattern_number": i + 1
            }

    # All patterns passed — input is clean
    return {
        "is_safe": True,
        "threat_level": "none",
        "matched_pattern": None,
        "message": "Input is clean"
    }


def scan_all_inputs(form_data: dict, ip: str = "unknown") -> dict:
    """
    Scan ALL fields in a form/request at once.
    
    Args:
        form_data: dict of {field_name: value}
        ip: requester IP
    
    Returns:
        {
            "all_safe": True/False,
            "threats": [...list of detected threats...]
        }
    """
    threats = []
    
    for field_name, value in form_data.items():
        if isinstance(value, str):
            result = detect_sql_injection(value, field_name, ip)
            if not result["is_safe"]:
                threats.append({
                    "field": field_name,
                    "threat_level": result["threat_level"],
                    "message": result["message"]
                })

    return {
        "all_safe": len(threats) == 0,
        "threats": threats
    }


def get_attack_stats() -> dict:
    """
    Read attack.log and return statistics for the dashboard.
    """
    stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "recent": []}
    
    try:
        with open("attack.log", "r") as f:
            lines = f.readlines()
            
        for line in lines:
            if "SQLi DETECTED" in line:
                stats["total"] += 1
                if "critical" in line.lower():
                    stats["critical"] += 1
                elif "high" in line.lower():
                    stats["high"] += 1
                else:
                    stats["medium"] += 1

        # Return last 10 attacks for dashboard
        stats["recent"] = [l.strip() for l in lines[-10:] if "SQLi DETECTED" in l]
        
    except FileNotFoundError:
        pass  # No attacks yet

    return stats