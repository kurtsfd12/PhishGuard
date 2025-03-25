import re
import logging
import html
import nltk
import os
from nltk.tokenize import word_tokenize, sent_tokenize

# Configure logging
logger = logging.getLogger(__name__)

# Create nltk_data directory if it doesn't exist
nltk_data_dir = os.path.join(os.path.expanduser('~'), 'nltk_data')
os.makedirs(nltk_data_dir, exist_ok=True)

# Download required NLTK data packages
nltk.download('punkt', download_dir=nltk_data_dir, quiet=True)

# Set the path for NLTK data
nltk.data.path.append(nltk_data_dir)

# List of common phishing keywords indicating urgency
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'alert', 'warning', 'attention', 'important',
    'verify', 'suspend', 'restricted', 'blocked', 'unauthorized', 'limited time',
    'expire', 'deadline', 'critical', 'act now', 'update required', 'security alert'
]

# List of keywords suggesting request for sensitive information
SENSITIVE_INFO_KEYWORDS = [
    'password', 'credit card', 'ssn', 'social security', 'account number',
    'security question', 'secure', 'verify your account', 'confirm your identity',
    'login', 'username', 'credentials', 'banking details', 'payment information',
    'personal details', 'click here', 'log in', 'sign in', 'verification required'
]

# List of common grammar and spelling mistakes often found in phishing emails
GRAMMAR_ISSUES = [
    'kindly', 'valued customer', 'dear customer', 'dear user', 'official mail',
    'your account will be', 'your account has been', 'we detected suspicious',
    'unusual activity', 'verify your information', 'money transfer', 'prize'
]

def analyze_email_content(subject, content):
    """
    Analyze email content for potential phishing indicators
    
    Args:
        subject (str): The email subject
        content (str): The email body content
        
    Returns:
        dict: Analysis results including score and highlighted content
    """
    logger.debug("Analyzing email content")
    
    # Combine subject and content for complete analysis
    full_text = f"{subject} {content}"
    full_text_lower = full_text.lower()
    
    # Initialize counters
    urgency_count = 0
    sensitive_info_count = 0
    grammar_issues_count = 0
    
    # Detect urgency keywords
    urgency_detected = False
    for keyword in URGENCY_KEYWORDS:
        if keyword.lower() in full_text_lower:
            urgency_count += 1
            urgency_detected = True
    
    # Detect sensitive information requests
    sensitive_info_requested = False
    for keyword in SENSITIVE_INFO_KEYWORDS:
        if keyword.lower() in full_text_lower:
            sensitive_info_count += 1
            sensitive_info_requested = True
    
    # Detect grammar issues common in phishing
    for issue in GRAMMAR_ISSUES:
        if issue.lower() in full_text_lower:
            grammar_issues_count += 1
    
    # Calculate the phishing likelihood score (between 0 and 1)
    # Using a weighted approach based on detected indicators
    urgency_weight = 0.3
    sensitive_info_weight = 0.5
    grammar_weight = 0.2
    
    max_urgency = len(URGENCY_KEYWORDS) / 4  # Assuming more than 25% is suspicious
    max_sensitive = len(SENSITIVE_INFO_KEYWORDS) / 4
    max_grammar = len(GRAMMAR_ISSUES) / 3
    
    urgency_score = min(1.0, urgency_count / max_urgency) * urgency_weight
    sensitive_score = min(1.0, sensitive_info_count / max_sensitive) * sensitive_info_weight
    grammar_score = min(1.0, grammar_issues_count / max_grammar) * grammar_weight
    
    total_score = urgency_score + sensitive_score + grammar_score
    
    # Generate highlighted HTML content
    highlighted_content = highlight_suspicious_content(content, subject)
    
    # Get the most suspicious phrases
    suspicious_phrases = get_suspicious_phrases(full_text)
    
    return {
        'score': total_score,
        'urgency_detected': urgency_detected,
        'sensitive_info_requested': sensitive_info_requested,
        'urgency_keywords': urgency_count,
        'sensitive_info_keywords': sensitive_info_count,
        'grammar_issues': grammar_issues_count,
        'suspicious_phrases': len(suspicious_phrases),
        'highlighted_content': highlighted_content
    }

def highlight_suspicious_content(content, subject):
    """
    Create HTML with highlighted suspicious elements
    
    Args:
        content (str): The email content
        subject (str): The email subject
        
    Returns:
        str: HTML with highlighted suspicious elements
    """
    # Escape HTML entities to prevent XSS attacks
    escaped_content = html.escape(content)
    escaped_subject = html.escape(subject)
    
    # Highlight subject if it contains suspicious keywords
    highlighted_subject = escaped_subject
    for keyword in URGENCY_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted_subject = pattern.sub(
            lambda m: f'<span class="suspicious-urgent">{m.group(0)}</span>',
            highlighted_subject
        )
    
    for keyword in SENSITIVE_INFO_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted_subject = pattern.sub(
            lambda m: f'<span class="suspicious-sensitive">{m.group(0)}</span>',
            highlighted_subject
        )
    
    # Highlight content based on different suspicious patterns
    highlighted_content = escaped_content
    
    # Highlight urgency keywords
    for keyword in URGENCY_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted_content = pattern.sub(
            lambda m: f'<span class="suspicious-urgent">{m.group(0)}</span>',
            highlighted_content
        )
    
    # Highlight sensitive info keywords
    for keyword in SENSITIVE_INFO_KEYWORDS:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted_content = pattern.sub(
            lambda m: f'<span class="suspicious-sensitive">{m.group(0)}</span>',
            highlighted_content
        )
    
    # Highlight grammar issues
    for keyword in GRAMMAR_ISSUES:
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted_content = pattern.sub(
            lambda m: f'<span class="suspicious-grammar">{m.group(0)}</span>',
            highlighted_content
        )
    
    # Highlight URLs
    url_pattern = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)
    highlighted_content = url_pattern.sub(
        lambda m: f'<span class="suspicious-link">{m.group(0)}</span>',
        highlighted_content
    )
    
    # Format with subject line
    replaced_content = highlighted_content.replace('\n', '<br>')
    complete_html = f"<strong>Subject:</strong> {highlighted_subject}<br><br>{replaced_content}"
    
    return complete_html

def get_suspicious_phrases(text):
    """
    Extract the most suspicious phrases from the email text
    
    Args:
        text (str): The email text (subject + content)
        
    Returns:
        list: List of suspicious phrases
    """
    suspicious_phrases = []
    
    # Tokenize into sentences
    try:
        sentences = sent_tokenize(text)
        
        # Analyze each sentence for suspicious content
        for sentence in sentences:
            sentence_lower = sentence.lower()
            
            # Check for urgency, sensitive info requests, and grammar issues
            urgency_score = sum(1 for keyword in URGENCY_KEYWORDS if keyword.lower() in sentence_lower)
            sensitive_score = sum(1 for keyword in SENSITIVE_INFO_KEYWORDS if keyword.lower() in sentence_lower)
            grammar_score = sum(1 for issue in GRAMMAR_ISSUES if issue.lower() in sentence_lower)
            
            # If sentence contains multiple indicators, add it to suspicious phrases
            if (urgency_score + sensitive_score + grammar_score) >= 2:
                suspicious_phrases.append(sentence.strip())
    except Exception as e:
        logger.error(f"Error analyzing sentences: {str(e)}")
    
    return suspicious_phrases
