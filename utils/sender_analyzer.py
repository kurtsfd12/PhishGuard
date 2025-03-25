import re
import logging
from email.utils import parseaddr

# Configure logging
logger = logging.getLogger(__name__)

# Common trusted email domains
TRUSTED_DOMAINS = {
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com',
    'icloud.com', 'me.com', 'mac.com', 'mail.com', 'protonmail.com',
    'zoho.com', 'yandex.com', 'gmx.com', 'live.com', 'msn.com',
    'comcast.net', 'verizon.net', 'att.net', 'facebook.com', 'twitter.com',
    'linkedin.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com'
}

# Patterns that indicate potential spoofing or misrepresentation
SUSPICIOUS_PATTERNS = [
    r'security', r'admin', r'verify', r'service', r'support', r'update',
    r'account', r'secure', r'bank', r'paypal', r'payment', r'confirm',
    r'invoice', r'order', r'shipping', r'delivery', r'notification'
]

def analyze_sender(sender_email):
    """
    Analyze sender email address for potential phishing indicators
    
    Args:
        sender_email (str): The sender's email address
        
    Returns:
        dict: Analysis results including score and summary
    """
    logger.debug(f"Analyzing sender: {sender_email}")
    
    # Parse the email address
    display_name, email_address = parseaddr(sender_email)
    
    # Initialize variables
    score = 0
    suspicious_indicators = []
    
    # If parsing failed, that's suspicious
    if not email_address or '@' not in email_address:
        return {
            'score': 0.8,
            'email_address': sender_email,
            'display_name': '',
            'domain': '',
            'suspicious_indicators': ['Invalid email format'],
            'summary': 'Invalid email format'
        }
    
    # Extract the domain
    try:
        domain = email_address.split('@')[1].lower()
    except IndexError:
        domain = ''
        score += 0.8
        suspicious_indicators.append('Malformed email address')
    
    # Check if domain is from trusted providers
    if domain and domain not in TRUSTED_DOMAINS:
        score += 0.3
        suspicious_indicators.append('Uncommon email domain')
    
    # Check display name for suspicious keywords
    if display_name:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, display_name.lower()):
                score += 0.2
                suspicious_indicators.append(f'Suspicious keyword in display name: {pattern}')
                break
    
    # Check for mismatch between display name and email domain
    if display_name and domain:
        # Extract potential company name from display name (e.g., "John from PayPal")
        company_match = re.search(r'from (\w+)', display_name.lower())
        if company_match:
            company = company_match.group(1)
            if company.lower() not in domain:
                score += 0.4
                suspicious_indicators.append(f'Display name mentions {company} but email is from {domain}')
        
        # Check if display name suggests a well-known company
        common_companies = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 
                          'bank', 'chase', 'wells fargo', 'citi', 'amex', 'visa', 'mastercard']
        for company in common_companies:
            if company in display_name.lower() and company not in domain:
                score += 0.5
                suspicious_indicators.append(f'Display name suggests {company} but email is from {domain}')
                break
    
    # Check for numbers in domain (can indicate temporary domains)
    if domain and re.search(r'\d', domain):
        score += 0.1
        suspicious_indicators.append('Domain contains numbers')
    
    # Check for excessive subdomains
    if domain and domain.count('.') > 2:
        score += 0.2
        suspicious_indicators.append('Excessive subdomains')
    
    # Check for long domain names (potential typosquatting)
    if domain and len(domain) > 30:
        score += 0.1
        suspicious_indicators.append('Unusually long domain name')
    
    # Check for lookalike domains (typosquatting)
    for trusted_domain in TRUSTED_DOMAINS:
        if domain and trusted_domain != domain and trusted_domain in domain:
            # Check for character swap typosquatting
            if len(domain) - len(trusted_domain) <= 3:
                score += 0.5
                suspicious_indicators.append(f'Possible typosquatting of {trusted_domain}')
                break
    
    # Cap score at 1.0
    score = min(1.0, score)
    
    # Create summary text
    if score >= 0.7:
        risk = "High"
        summary = "Highly suspicious sender address"
    elif score >= 0.4:
        risk = "Medium"
        summary = "Moderately suspicious sender address"
    else:
        risk = "Low"
        summary = "Low-risk sender address"
    
    if suspicious_indicators:
        summary += f": {', '.join(suspicious_indicators)}"
    
    return {
        'score': score,
        'email_address': email_address,
        'display_name': display_name,
        'domain': domain,
        'risk': risk,
        'suspicious_indicators': suspicious_indicators,
        'summary': summary
    }
