import os
import logging
from flask import Flask, render_template, request, jsonify
from utils.email_analyzer import analyze_email_content
from utils.url_analyzer import analyze_urls
from utils.sender_analyzer import analyze_sender

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_dev")

@app.route('/')
def index():
    """Render the main page of the application"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the submitted email and return results"""
    try:
        # Get the email data from the form
        email_data = request.form.get('email_content', '')
        email_subject = request.form.get('email_subject', '')
        email_sender = request.form.get('email_sender', '')
        
        logger.debug(f"Received analysis request:\nSender: {email_sender}\nSubject: {email_subject}\nContent length: {len(email_data)}")
        
        # Analyze the different components of the email
        content_results = analyze_email_content(email_subject, email_data)
        url_results = analyze_urls(email_data)
        sender_results = analyze_sender(email_sender)
        
        # Calculate overall phishing score (0-100)
        # Each category contributes a portion to the total score
        content_weight = 0.4
        url_weight = 0.4
        sender_weight = 0.2
        
        overall_score = (
            content_results['score'] * content_weight +
            url_results['score'] * url_weight +
            sender_results['score'] * sender_weight
        ) * 100
        
        # Determine risk level
        risk_level = "Low"
        if overall_score > 70:
            risk_level = "High"
        elif overall_score > 40:
            risk_level = "Medium"
        
        # Prepare the response with all analysis results
        results = {
            'overall_score': round(overall_score, 1),
            'risk_level': risk_level,
            'content_analysis': content_results,
            'url_analysis': url_results,
            'sender_analysis': sender_results,
            'highlighted_content': content_results['highlighted_content'],
            'educational_tips': generate_educational_tips(content_results, url_results, sender_results)
        }
        
        return jsonify(results)
    
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        return jsonify({
            'error': f"An error occurred while analyzing the email: {str(e)}",
            'overall_score': 0,
            'risk_level': 'Unknown'
        }), 500

def generate_educational_tips(content_results, url_results, sender_results):
    """Generate educational tips based on detected phishing indicators"""
    tips = []
    
    # Add tips based on content analysis
    if content_results['urgency_detected']:
        tips.append({
            'category': 'Content',
            'title': 'Urgency Tactics',
            'description': 'Phishers often create a false sense of urgency to make you act without thinking. Take time to verify requests that pressure you to act immediately.'
        })
    
    if content_results['sensitive_info_requested']:
        tips.append({
            'category': 'Content',
            'title': 'Personal Information Requests',
            'description': 'Legitimate organizations rarely request sensitive information like passwords or credit card details via email.'
        })
    
    # Add tips based on URL analysis
    if url_results['suspicious_urls'] > 0:
        tips.append({
            'category': 'Links',
            'title': 'Suspicious Links',
            'description': 'Always hover over links to see the actual URL before clicking. Be wary of URLs that mimic legitimate domains with slight spelling variations.'
        })
    
    # Add tips based on sender analysis
    if sender_results['score'] > 0.5:
        tips.append({
            'category': 'Sender',
            'title': 'Sender Verification',
            'description': 'Check the email address carefully. Phishers often use email addresses that look similar to legitimate ones but with small differences.'
        })
    
    # Always include some general tips
    tips.append({
        'category': 'General',
        'title': 'When in Doubt',
        'description': "If you're unsure about an email, contact the purported sender directly using contact information from their official website, not from the email itself."
    })
    
    return tips

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
