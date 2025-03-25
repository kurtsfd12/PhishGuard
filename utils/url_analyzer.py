import re
import logging
from urllib.parse import urlparse, parse_qs

# Configure logging
logger = logging.getLogger(__name__)

# Common trusted domains for email communications
TRUSTED_DOMAINS = {
    'google.com', 'gmail.com', 'outlook.com', 'office.com', 'microsoft.com',
    'yahoo.com', 'apple.com', 'icloud.com', 'amazon.com', 'linkedin.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'paypal.com', 'dropbox.com',
    'github.com', 'gitlab.com', 'adobe.com', 'zoom.us', 'slack.com'
}

# Suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'info', 'biz', 'gq', 'ml', 'cf', 
    'ga', 'tk', 'work', 'date', 'review', 'bid', 'stream', 'racing', 'win'
}

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'paypal.*\.com',      # Not paypal.com but something like paypal-secure.com
    r'secure.*\.com',      # Domains trying to appear secure
    r'verify.*\.com',      # Domains about verification
    r'account.*\.com',     # Domains about accounts
    r'banking.*\.com',     # Banking related
    r'login.*\.com',       # Login related
    r'signin.*\.com',      # Sign in related
    r'update.*\.com',      # Update related
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
    r'bit\.ly',            # URL shorteners
    r'goo\.gl', 
    r'tinyurl\.com',
    r'is\.gd'
]

def analyze_urls(content):
    """
    Analyze URLs in email content for potential phishing indicators
    
    Args:
        content (str): The email content
        
    Returns:
        dict: Analysis results including score and URL details
    """
    logger.debug("Analyzing URLs in email content")
    
    # Extract URLs from the content
    urls = extract_urls(content)
    total_urls = len(urls)
    suspicious_urls = 0
    url_analysis = []
    
    # Analyze each URL
    for url in urls:
        url_info = analyze_url(url)
        url_analysis.append(url_info)
        
        if url_info['risk_level'] in ['Medium', 'High']:
            suspicious_urls += 1
    
    # Calculate phishing likelihood score (between 0 and 1)
    score = 0
    if total_urls > 0:
        score = suspicious_urls / total_urls
        
        # Increase score if there are many URLs
        if total_urls > 3 and suspicious_urls > 0:
            score = min(1.0, score + 0.1)
    
    return {
        'score': score,
        'total_urls': total_urls,
        'suspicious_urls': suspicious_urls,
        'urls': url_analysis
    }

def extract_urls(content):
    """
    Extract URLs from the email content
    
    Args:
        content (str): The email content
        
    Returns:
        list: List of URLs found in the content
    """
    # Pattern to match URLs
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    
    # Find all matches
    matches = url_pattern.findall(content)
    
    # Clean up matches (remove trailing punctuation, etc.)
    cleaned_urls = []
    for match in matches:
        # Remove trailing punctuation or closing parentheses
        url = re.sub(r'[.,;:"\')]$', '', match)
        cleaned_urls.append(url)
    
    return cleaned_urls

def analyze_url(url):
    """
    Analyze a single URL for suspicious characteristics
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: URL analysis results
    """
    # Ensure URL starts with a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Initialize risk level and reason
        risk_level = "Low"
        reasons = []
        
        # Check for IP address as domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            risk_level = "High"
            reasons.append("IP address used instead of domain name")
        
        # Check for suspicious TLDs
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in SUSPICIOUS_TLDS:
            if risk_level != "High":
                risk_level = "Medium"
            reasons.append(f"Suspicious TLD (.{tld})")
        
        # Check for suspicious domain patterns
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, domain):
                risk_level = "High"
                reasons.append("Suspicious domain pattern")
                break
        
        # Check for lookalike domains (typosquatting)
        for trusted in TRUSTED_DOMAINS:
            # Calculate similarity or check for substrings
            if trusted != domain and trusted in domain:
                risk_level = "High"
                reasons.append(f"Possible lookalike domain of {trusted}")
                break
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count >= 3:
            if risk_level != "High":
                risk_level = "Medium"
            reasons.append(f"Excessive subdomains ({subdomain_count})")
        
        # Check query parameters for suspicious content
        query_params = parse_qs(parsed_url.query)
        suspicious_params = ['token', 'password', 'login', 'redirect', 'return', 'returnTo', 'goto']
        for param in suspicious_params:
            if param in query_params:
                if risk_level != "High":
                    risk_level = "Medium"
                reasons.append(f"Suspicious query parameter: {param}")
                break
        
        # If no reasons found but not a common trusted domain
        if not reasons and domain not in TRUSTED_DOMAINS:
            if any(trusted in domain for trusted in TRUSTED_DOMAINS):
                risk_level = "Medium"
                reasons.append("Similar to trusted domain but not exact match")
            else:
                reasons.append("Unknown domain")
        
        # If no reasons found and is a trusted domain
        if not reasons:
            reasons.append("Trusted domain")
        
        return {
            'url': url,
            'domain': domain,
            'risk_level': risk_level,
            'reason': "; ".join(reasons)
        }
    
    except Exception as e:
        logger.error(f"Error analyzing URL '{url}': {str(e)}")
        return {
            'url': url,
            'domain': 'Error parsing',
            'risk_level': 'Unknown',
            'reason': f"Error analyzing URL: {str(e)}"
        }
