"""
Traffic Classification Module
Classifies raw traffic data by threat level using multi-factor analysis
"""

import re
import json
from pathlib import Path

# Load signatures
def load_signatures():
    """Load bot signatures and patterns from JSON file"""
    signatures_file = Path(__file__).parent / 'bot_signatures.json'
    with open(signatures_file, 'r') as f:
        return json.load(f)

# Cache signatures at module level
SIGNATURES = load_signatures()

def classify_traffic(user_agent, path):
    """
    Classify traffic using multiple factors:
    - User-agent patterns
    - Path patterns
    - Combined threat scoring
    
    Returns: (category, threat_level, threat_score)
    """
    score = 0
    categories = []
    
    user_agent_lower = user_agent.lower()
    path_lower = path.lower()
    
    # Factor 1: User-agent classification
    ua_category, ua_score = classify_user_agent(user_agent_lower)
    if ua_category:
        categories.append(ua_category)
        score += ua_score
    
    # Factor 2: Path pattern analysis
    path_categories, path_score = classify_path(path_lower)
    categories.extend(path_categories)
    score += path_score
    
    # Determine threat level based on final score
    if score < 0:
        threat_level = "benign"
    elif score < 20:
        threat_level = "reconnaissance"
    else:
        threat_level = "malicious"
    
    # Primary category is the most specific match
    if categories:
        primary_category = categories[0]
    else:
        primary_category = "unknown"
    
    return primary_category, threat_level, score

def classify_traffic_detailed(user_agent, path):
    """
    Classify traffic with detailed pattern matching info
    
    Returns: dict with category, threat_level, score, and matched patterns
    """
    score = 0
    categories = []
    matched_patterns = []
    
    user_agent_lower = user_agent.lower()
    path_lower = path.lower()
    
    # Factor 1: User-agent classification
    ua_category, ua_score, ua_pattern = classify_user_agent_detailed(user_agent_lower)
    if ua_category:
        categories.append(ua_category)
        score += ua_score
        if ua_pattern:
            matched_patterns.append(ua_pattern)
    
    # Factor 2: Path pattern analysis
    path_categories, path_score, path_patterns = classify_path_detailed(path_lower)
    categories.extend(path_categories)
    score += path_score
    matched_patterns.extend(path_patterns)
    
    # Determine threat level based on final score
    if score < 0:
        threat_level = "benign"
    elif score < 20:
        threat_level = "reconnaissance"
    else:
        threat_level = "malicious"
    
    # Primary category is the most specific match
    if categories:
        primary_category = categories[0]
    else:
        primary_category = "unknown"
    
    return {
        'category': primary_category,
        'threat_level': threat_level,
        'threat_score': score,
        'matched_patterns': matched_patterns
    }

def classify_user_agent(user_agent_lower):
    """Classify based on user-agent string"""
    # Check benign bots first
    for bot_type, config in SIGNATURES.get('benign', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"benign_{bot_type}", config.get('threat_score', -10))
    
    # Check security scanners
    for bot_type, config in SIGNATURES.get('security_scanners', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"scanner_{bot_type}", config.get('threat_score', 20))
    
    # Check generic clients
    for bot_type, config in SIGNATURES.get('generic_clients', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"generic_{bot_type}", config.get('threat_score', 5))
    
    return (None, 0)

def classify_user_agent_detailed(user_agent_lower):
    """Classify based on user-agent string with pattern details"""
    # Check benign bots first
    for bot_type, config in SIGNATURES.get('benign', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"benign_{bot_type}", config.get('threat_score', -10), 
                       f"User-Agent matches {bot_type}: {pattern}")
    
    # Check security scanners
    for bot_type, config in SIGNATURES.get('security_scanners', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"scanner_{bot_type}", config.get('threat_score', 20),
                       f"Security scanner detected: {pattern}")
    
    # Check generic clients
    for bot_type, config in SIGNATURES.get('generic_clients', {}).items():
        for pattern in config.get('user_agents', []):
            if pattern.lower() in user_agent_lower:
                return (f"generic_{bot_type}", config.get('threat_score', 5),
                       f"Generic HTTP client: {pattern}")
    
    return (None, 0, None)

def classify_path(path_lower):
    """Classify based on requested path using regex patterns"""
    categories = []
    total_score = 0
    
    # Check reconnaissance patterns
    for recon_type, config in SIGNATURES.get('reconnaissance', {}).items():
        for pattern in config.get('path_patterns', []):
            if re.search(pattern, path_lower, re.IGNORECASE):
                categories.append(f"recon_{recon_type}")
                total_score += config.get('threat_score', 10)
                break  # Only count once per category
    
    # Check malicious patterns (higher priority)
    for malicious_type, config in SIGNATURES.get('malicious', {}).items():
        for pattern in config.get('path_patterns', []):
            if re.search(pattern, path_lower, re.IGNORECASE):
                categories.insert(0, f"malicious_{malicious_type}")  # Priority
                total_score += config.get('threat_score', 50)
                break
    
    return (categories, total_score)

def classify_path_detailed(path_lower):
    """Classify based on requested path with pattern details"""
    categories = []
    total_score = 0
    matched_patterns = []
    
    # Check reconnaissance patterns
    for recon_type, config in SIGNATURES.get('reconnaissance', {}).items():
        for pattern in config.get('path_patterns', []):
            if re.search(pattern, path_lower, re.IGNORECASE):
                categories.append(f"recon_{recon_type}")
                total_score += config.get('threat_score', 10)
                description = config.get('description', recon_type.replace('_', ' ').title())
                matched_patterns.append(f"Path pattern: {description}")
                break  # Only count once per category
    
    # Check malicious patterns (higher priority)
    for malicious_type, config in SIGNATURES.get('malicious', {}).items():
        for pattern in config.get('path_patterns', []):
            if re.search(pattern, path_lower, re.IGNORECASE):
                categories.insert(0, f"malicious_{malicious_type}")  # Priority
                total_score += config.get('threat_score', 50)
                description = config.get('description', malicious_type.replace('_', ' ').title())
                matched_patterns.insert(0, f"Malicious pattern: {description}")
                break
    
    return (categories, total_score, matched_patterns)

def classify_entry(entry):
    """
    Classify a single database entry
    Returns dict with original entry plus classification fields
    """
    category, threat_level, threat_score = classify_traffic(
        entry.get('user_agent', ''),
        entry.get('path', '')
    )
    
    return {
        **entry,
        'category': category,
        'threat_level': threat_level,
        'threat_score': threat_score
    }

def classify_entries(entries):
    """
    Classify multiple entries
    Returns list of classified entries
    """
    return [classify_entry(entry) for entry in entries]

