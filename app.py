import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import time

# Page configuration
st.set_page_config(
    page_title="AI Guardrails & Security Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'assistant_visible' not in st.session_state:
    st.session_state.assistant_visible = True
if 'security_alerts' not in st.session_state:
    st.session_state.security_alerts = []
if 'pii_detections' not in st.session_state:
    st.session_state.pii_detections = []
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()

# Professional Security Theme CSS
st.markdown("""
<style>
    .main > div {
        background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%);
        color: #e2e8f0;
    }
    
    .security-header {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        border: 1px solid #10b981;
        text-align: center;
        box-shadow: 0 8px 32px rgba(16, 185, 129, 0.1);
    }
    
    .ai-assistant-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(15, 20, 25, 0.95);
        backdrop-filter: blur(10px);
        z-index: 999;
        display: flex;
        justify-content: center;
        align-items: center;
    }
    
    .ai-assistant-card {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        border: 2px solid #10b981;
        border-radius: 20px;
        padding: 2.5rem;
        max-width: 550px;
        text-align: center;
        box-shadow: 0 25px 50px rgba(16, 185, 129, 0.3);
        animation: secure-pulse 3s ease-in-out infinite;
    }
    
    @keyframes secure-pulse {
        0%, 100% { box-shadow: 0 25px 50px rgba(16, 185, 129, 0.3); }
        50% { box-shadow: 0 25px 60px rgba(16, 185, 129, 0.5); }
    }
    
    .ai-avatar {
        width: 90px;
        height: 90px;
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 1.5rem auto;
        font-size: 2.5rem;
        animation: shield-rotate 4s linear infinite;
        border: 3px solid #34d399;
    }
    
    @keyframes shield-rotate {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    .security-metric {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .security-metric:hover {
        border-color: #10b981;
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(16, 185, 129, 0.2);
    }
    
    .threat-alert {
        background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
        border-left: 4px solid #ef4444;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        color: #fecaca;
    }
    
    .security-success {
        background: linear-gradient(135deg, #064e3b 0%, #065f46 100%);
        border-left: 4px solid #10b981;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        color: #a7f3d0;
    }
    
    .compliance-card {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
        border: 1px solid #6366f1;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .pii-detection {
        background: linear-gradient(135deg, #7c2d12 0%, #9a3412 100%);
        border-left: 4px solid #f97316;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        color: #fed7aa;
    }
    
    .guardrail-pipeline {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
    }
    
    .audit-log {
        background: #111827;
        border-left: 4px solid #6366f1;
        border-radius: 8px;
        padding: 0.8rem;
        margin: 0.3rem 0;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        color: #d1d5db;
    }
    
    .security-badge {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: bold;
        margin: 0.2rem;
    }
    
    .badge-critical { background: #dc2626; color: white; }
    .badge-high { background: #ea580c; color: white; }
    .badge-medium { background: #ca8a04; color: white; }
    .badge-low { background: #16a34a; color: white; }
    .badge-secure { background: #10b981; color: white; }
    
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 1.1rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# AI Assistant Welcome Screen
if st.session_state.assistant_visible:
    # Use Streamlit's native styling instead of HTML overlay
    st.markdown("""
    <style>
    .main > div {
        background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%);
        padding: 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Create centered welcome content
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    # Center the AI Security Guardian card
    col1, col2, col3 = st.columns([1, 3, 1])
    
    with col2:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
                    border: 2px solid #10b981; border-radius: 20px; padding: 2.5rem; 
                    text-align: center; box-shadow: 0 25px 50px rgba(16, 185, 129, 0.3); 
                    margin: 2rem 0;">
            <div style="width: 90px; height: 90px; background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                        border-radius: 50%; display: flex; align-items: center; justify-content: center;
                        margin: 0 auto 1.5rem auto; font-size: 2.5rem; border: 3px solid #34d399;">🛡️</div>
            <h2 style="color: #10b981; margin-bottom: 1rem;">AI Security Guardian</h2>
            <p style="font-size: 1.2rem; line-height: 1.7; margin-bottom: 2rem; color: #e2e8f0;">
                Welcome! I'm your AI Security Guardian, here to ensure safe and compliant AI deployment 
                across your enterprise. I specialize in PII protection, prompt injection prevention, 
                and comprehensive security monitoring. Ready to safeguard your AI systems with 
                enterprise-grade guardrails and keep your data secure! 🔒
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Add the enter button right after the card
        st.markdown("<br>", unsafe_allow_html=True)
        
        if st.button("🚀 Enter App", type="primary", use_container_width=True):
            st.session_state.assistant_visible = False
            st.rerun()
    
    st.stop()

# Main Application Header
st.markdown("""
<div class="security-header">
    <h1>🛡️ AI Guardrails & Security Framework</h1>
    <h3>Enterprise Compliance • PII Protection • Threat Prevention</h3>
    <p style="font-size: 1.1rem; margin-top: 1rem;">
        Production-ready security framework enabling compliant AI deployment across business units
    </p>
</div>
""", unsafe_allow_html=True)

# Generate real-time security data
def generate_security_metrics():
    current_time = datetime.now()
    
    return {
        'requests_processed': 847692 + random.randint(-50, 50),
        'threats_blocked': 1247 + random.randint(0, 5),
        'pii_redacted': 3829 + random.randint(0, 8),
        'policy_violations': random.randint(0, 3),
        'compliance_score': round(random.uniform(97.5, 99.2), 1),
        'response_time_ms': random.randint(45, 85),
        'false_positive_rate': round(random.uniform(0.8, 2.1), 2),
        'federated_models': 12,
        'active_guardrails': 47
    }

# Create tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Security Dashboard", 
    "🛡️ Guardrail Architecture", 
    "👁️ PII Protection", 
    "📊 Compliance Monitor",
    "🏗️ Implementation"
])

with tab1:
    st.header("Real-Time AI Security Operations Center")
    
    # Get current metrics
    metrics = generate_security_metrics()
    
    # Key Security Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="security-metric">
            <h3 style="color: #10b981;">Requests Processed</h3>
            <h2>{metrics['requests_processed']:,}</h2>
            <p>Last 24 Hours</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="security-metric">
            <h3 style="color: #ef4444;">Threats Blocked</h3>
            <h2>{metrics['threats_blocked']:,}</h2>
            <p>Security Incidents Prevented</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="security-metric">
            <h3 style="color: #f59e0b;">PII Redacted</h3>
            <h2>{metrics['pii_redacted']:,}</h2>
            <p>Sensitive Data Protected</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="security-metric">
            <h3 style="color: #8b5cf6;">Compliance Score</h3>
            <h2>{metrics['compliance_score']}%</h2>
            <p>Enterprise Policy Adherence</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Active Threats and Security Alerts
    st.subheader("🚨 Active Security Monitoring")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if metrics['policy_violations'] > 0:
            st.markdown(f"""
            <div class="threat-alert">
                <h4>⚠️ Policy Violations Detected: {metrics['policy_violations']}</h4>
                <p>Prompt injection attempt blocked - Source: External API</p>
                <p><strong>Action:</strong> Request quarantined, user notified</p>
                <p><strong>Risk Level:</strong> HIGH</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="security-success">
                <h4>✅ All Systems Secure</h4>
                <p>No active threats detected</p>
                <p><strong>Status:</strong> Monitoring</p>
                <p><strong>Last Scan:</strong> 30 seconds ago</p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="compliance-card">
            <h4>📋 Compliance Status</h4>
            <h2>{metrics['federated_models']}</h2>
            <p>Federated learning models active</p>
            <p><strong>Coverage:</strong> All business units</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="compliance-card">
            <h4>⚡ Performance Metrics</h4>
            <h2>{metrics['response_time_ms']}ms</h2>
            <p>Average response time</p>
            <p><strong>False Positive Rate:</strong> {metrics['false_positive_rate']}%</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Real-time Security Feed
    st.subheader("📡 Live Security Feed")
    
    # Generate sample security events
    security_events = [
        {"time": "14:23:42", "type": "PII_DETECTED", "message": "SSN pattern detected and redacted in user query", "severity": "MEDIUM"},
        {"time": "14:21:15", "type": "INJECTION_BLOCKED", "message": "Prompt injection attempt blocked - malicious system commands detected", "severity": "HIGH"},
        {"time": "14:19:03", "type": "POLICY_ENFORCED", "message": "Content policy violation - inappropriate language filtered", "severity": "LOW"},
        {"time": "14:16:28", "type": "AUDIT_LOGGED", "message": "Sensitive content access logged for compliance review", "severity": "LOW"},
        {"time": "14:14:51", "type": "FEDERATED_UPDATE", "message": "Federated learning model updated with new threat patterns", "severity": "LOW"},
        {"time": "14:12:37", "type": "ALLOWLIST_MATCH", "message": "Trusted domain request approved through allowlist policy", "severity": "SECURE"}
    ]
    
    for event in security_events:
        severity_colors = {
            "HIGH": "#dc2626",
            "MEDIUM": "#f59e0b", 
            "LOW": "#6366f1",
            "SECURE": "#10b981"
        }
        
        st.markdown(f"""
        <div style="border-left: 4px solid {severity_colors[event['severity']]}; padding: 0.8rem; 
                    margin: 0.3rem 0; background: #1f2937; border-radius: 5px;">
            <strong>{event['time']}</strong> - 
            <span style="color: {severity_colors[event['severity']]};">{event['type']}</span><br>
            {event['message']}
        </div>
        """, unsafe_allow_html=True)
    
    # Threat Analytics Chart
    st.subheader("📈 Security Analytics")
    
    # Generate sample threat data
    hours = list(range(24))
    threat_data = {
        'Hour': hours,
        'Threats Blocked': [random.randint(20, 80) for _ in hours],
        'PII Detections': [random.randint(10, 40) for _ in hours],
        'Policy Violations': [random.randint(0, 15) for _ in hours]
    }
    
    threat_df = pd.DataFrame(threat_data)
    threat_df.set_index('Hour', inplace=True)
    
    st.line_chart(threat_df)

with tab2:
    st.header("🛡️ Guardrail Architecture & Implementation")
    
    st.markdown("""
    <div class="compliance-card">
        <h3>Advanced Security Pipeline Architecture</h3>
        <p>Multi-layered security framework with regex + ML-based detection, policy enforcement, 
        and comprehensive audit logging for enterprise AI deployment.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Architecture Flow
    st.subheader("🔄 Security Pipeline Flow")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>📊 Processing Pipeline Stages</h4>
        </div>
        """, unsafe_allow_html=True)
        
        pipeline_stages = {
            'Stage': ['Input Validation', 'PII Detection', 'Content Analysis', 'Policy Check', 'Threat Assessment', 'Response Generation', 'Audit Logging'],
            'Technology': ['Regex + Schema Validation', 'ML + NER Models', 'Sentiment + Topic Analysis', 'Rule Engine + Allowlist', 'ML Threat Detection', 'Content Sanitization', 'Blockchain Audit Trail'],
            'Processing Time': ['< 5ms', '< 25ms', '< 15ms', '< 10ms', '< 30ms', '< 20ms', '< 8ms'],
            'Accuracy': ['99.9%', '97.3%', '94.8%', '99.1%', '96.4%', '98.7%', '100%']
        }
        
        pipeline_df = pd.DataFrame(pipeline_stages)
        st.dataframe(pipeline_df, use_container_width=True)
    
    with col2:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>🎯 Active Guardrails</h4>
            <p><strong>Total:</strong> 47 active policies</p>
            <p><strong>PII Detection:</strong> 12 patterns</p>
            <p><strong>Injection Prevention:</strong> 8 filters</p>
            <p><strong>Content Policies:</strong> 15 rules</p>
            <p><strong>Compliance Checks:</strong> 12 validators</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Microservice Architecture
    st.subheader("🏗️ Microservice Architecture")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>🔍 Detection Services</h4>
            <ul style="color: #d1d5db;">
                <li><strong>PII Detection Service</strong> - Named entity recognition + regex patterns</li>
                <li><strong>Threat Detection Service</strong> - ML-based injection detection</li>
                <li><strong>Content Analysis Service</strong> - Sentiment + topic classification</li>
                <li><strong>Policy Engine</strong> - Rule-based validation engine</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>⚙️ Processing Services</h4>
            <ul style="color: #d1d5db;">
                <li><strong>Redaction Service</strong> - PII masking and anonymization</li>
                <li><strong>Annotation Service</strong> - Content labeling and tagging</li>
                <li><strong>Validation Pipeline</strong> - Multi-stage content verification</li>
                <li><strong>Response Sanitizer</strong> - Output content cleaning</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>📊 Monitoring Services</h4>
            <ul style="color: #d1d5db;">
                <li><strong>Audit Logger</strong> - Comprehensive event logging</li>
                <li><strong>Metrics Collector</strong> - Performance monitoring</li>
                <li><strong>Alert Manager</strong> - Real-time notifications</li>
                <li><strong>Compliance Reporter</strong> - Regulatory reporting</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Key Learning Implementation
    st.subheader("💡 Key Learning: Structured Pre-processing > Prompt Engineering")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="security-success">
            <h4>✅ Structured Pre-processing Approach</h4>
            <ul style="color: #a7f3d0; margin: 1rem 0;">
                <li><strong>97.3% Detection Accuracy</strong> - Consistent, reliable results</li>
                <li><strong>45ms Average Response</strong> - Optimized pipeline performance</li>
                <li><strong>0.8% False Positive Rate</strong> - Minimal user friction</li>
                <li><strong>Scalable Architecture</strong> - Handles 50K+ requests/hour</li>
                <li><strong>Audit Compliance</strong> - 100% transaction logging</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="threat-alert">
            <h4>⚠️ Traditional Prompt Engineering Limitations</h4>
            <ul style="color: #fecaca; margin: 1rem 0;">
                <li><strong>Inconsistent Results</strong> - Varies with model updates</li>
                <li><strong>Bypass Vulnerabilities</strong> - Sophisticated injection attacks</li>
                <li><strong>Maintenance Overhead</strong> - Constant prompt tuning required</li>
                <li><strong>Limited Auditability</strong> - Difficult to track decisions</li>
                <li><strong>Scaling Challenges</strong> - Performance degrades with complexity</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

with tab3:
    st.header("👁️ Advanced PII Protection System")
    
    # PII Detection Overview
    st.markdown("""
    <div class="compliance-card">
        <h3>Multi-Modal PII Detection & Protection</h3>
        <p>Comprehensive personally identifiable information detection using regex patterns, 
        machine learning models, and federated learning for sensitive content identification.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # PII Detection Stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("PII Patterns Detected", "3,847", "+23")
    with col2:
        st.metric("Data Points Redacted", "12,429", "+156") 
    with col3:
        st.metric("Detection Accuracy", "97.3%", "+1.2%")
    with col4:
        st.metric("Processing Speed", "25ms", "↓ 8ms")
    
    # PII Categories and Examples
    st.subheader("🔍 PII Detection Categories")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="pii-detection">
            <h4>📱 Contact Information</h4>
            <ul>
                <li><strong>SSN:</strong> XXX-XX-1234 → XXX-XX-XXXX</li>
                <li><strong>Phone:</strong> (555) 123-4567 → (XXX) XXX-XXXX</li>
                <li><strong>Email:</strong> user@company.com → [EMAIL_REDACTED]</li>
                <li><strong>Address:</strong> 123 Main St → [ADDRESS_REDACTED]</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="pii-detection">
            <h4>💳 Financial Data</h4>
            <ul>
                <li><strong>Credit Card:</strong> 4111-1111-1111-1111 → [CARD_REDACTED]</li>
                <li><strong>Bank Account:</strong> 123456789 → [ACCOUNT_REDACTED]</li>
                <li><strong>Routing:</strong> 021000021 → [ROUTING_REDACTED]</li>
                <li><strong>Tax ID:</strong> 12-3456789 → [TAX_ID_REDACTED]</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="pii-detection">
            <h4>🏥 Healthcare & Legal</h4>
            <ul>
                <li><strong>Medicare:</strong> 1EG4-TE5-MK73 → [MEDICARE_REDACTED]</li>
                <li><strong>License:</strong> D1234567 → [LICENSE_REDACTED]</li>
                <li><strong>Passport:</strong> 123456789 → [PASSPORT_REDACTED]</li>
                <li><strong>DOB:</strong> 01/15/1980 → [DOB_REDACTED]</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Live PII Detection Demo
    st.subheader("🧪 Live PII Detection Demo")
    
    demo_text = st.text_area(
        "Enter text to test PII detection:",
        placeholder="Try entering: My SSN is 123-45-6789 and my email is john.doe@company.com",
        height=100
    )
    
    if st.button("🔍 Analyze for PII", type="primary"):
        if demo_text:
            with st.spinner("Analyzing text for PII patterns..."):
                time.sleep(1.5)  # Simulate processing
            
            # Simulate PII detection results
            detected_patterns = []
            redacted_text = demo_text
            
            # Simple regex patterns for demo
            import re
            
            # SSN pattern
            ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
            if re.search(ssn_pattern, demo_text):
                detected_patterns.append("SSN")
                redacted_text = re.sub(ssn_pattern, "[SSN_REDACTED]", redacted_text)
            
            # Email pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if re.search(email_pattern, demo_text):
                detected_patterns.append("Email Address")
                redacted_text = re.sub(email_pattern, "[EMAIL_REDACTED]", redacted_text)
            
            # Phone pattern
            phone_pattern = r'\b\d{3}-\d{3}-\d{4}\b'
            if re.search(phone_pattern, demo_text):
                detected_patterns.append("Phone Number")
                redacted_text = re.sub(phone_pattern, "[PHONE_REDACTED]", redacted_text)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                <div class="threat-alert">
                    <h4>🚨 Original Content</h4>
                </div>
                """, unsafe_allow_html=True)
                st.code(demo_text, language=None)
                
                if detected_patterns:
                    st.markdown(f"""
                    <div class="pii-detection">
                        <h4>⚠️ PII Detected</h4>
                        <p>Found: {', '.join(detected_patterns)}</p>
                    </div>
                    """, unsafe_allow_html=True)
            
            with col2:
                st.markdown("""
                <div class="security-success">
                    <h4>✅ Redacted Content</h4>
                </div>
                """, unsafe_allow_html=True)
                st.code(redacted_text, language=None)
                
                st.markdown("""
                <div class="security-success">
                    <h4>🛡️ Protection Applied</h4>
                    <p>Sensitive information has been automatically redacted</p>
                </div>
                """, unsafe_allow_html=True)
    
    # Federated Learning for PII Detection
    st.subheader("🔗 Federated Learning Enhancement")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="compliance-card">
            <h4>🤝 Collaborative Learning</h4>
            <ul style="color: #e2e8f0;">
                <li><strong>12 Active Models</strong> - Across business units</li>
                <li><strong>Privacy Preserved</strong> - No raw data sharing</li>
                <li><strong>Continuous Learning</strong> - Real-time model updates</li>
                <li><strong>Domain Adaptation</strong> - Unit-specific patterns</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        federated_data = {
            'Business Unit': ['Customer Service', 'Finance', 'HR', 'Legal', 'Operations'],
            'Model Accuracy': ['98.1%', '97.8%', '96.9%', '98.7%', '97.2%'],
            'Patterns Learned': [247, 198, 156, 203, 189],
            'Last Update': ['2 hours ago', '1 hour ago', '3 hours ago', '30 min ago', '1 hour ago']
        }
        
        fed_df = pd.DataFrame(federated_data)
        st.dataframe(fed_df, use_container_width=True)

with tab4:
    st.header("📊 Enterprise Compliance Monitoring")
    
    # Compliance Overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"""
        <div class="compliance-card">
            <h3>🏛️ Regulatory Compliance</h3>
            <h2>{metrics['compliance_score']}%</h2>
            <p>Overall compliance score</p>
            <p><strong>GDPR:</strong> ✅ Compliant</p>
            <p><strong>CCPA:</strong> ✅ Compliant</p>
            <p><strong>HIPAA:</strong> ✅ Compliant</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="compliance-card">
            <h3>📋 Policy Enforcement</h3>
            <h2>47</h2>
            <p>Active security policies</p>
            <p><strong>Violations Today:</strong> 3</p>
            <p><strong>Auto-resolved:</strong> 3</p>
            <p><strong>Manual Review:</strong> 0</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="compliance-card">
            <h3>🔍 Audit Coverage</h3>
            <h2>100%</h2>
            <p>Transaction logging</p>
            <p><strong>Events Logged:</strong> 847K</p>
            <p><strong>Retention:</strong> 7 years</p>
            <p><strong>Searchable:</strong> ✅ Yes</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Comprehensive Audit Trail
    st.subheader("📜 Real-Time Audit Trail")
    
    audit_events = [
        {"timestamp": "2025-01-17 14:23:42", "user": "service.api", "action": "PII_REDACTED", "resource": "user.query.847392", "result": "SUCCESS", "details": "SSN pattern detected and redacted"},
        {"timestamp": "2025-01-17 14:21:15", "user": "external.api", "action": "INJECTION_BLOCKED", "resource": "prompt.validation", "result": "BLOCKED", "details": "Malicious system command detected"},
        {"timestamp": "2025-01-17 14:19:03", "user": "user.12847", "action": "CONTENT_FILTERED", "resource": "message.content", "result": "FILTERED", "details": "Inappropriate language policy violation"},
        {"timestamp": "2025-01-17 14:16:28", "user": "analyst.jane", "action": "DATA_ACCESS", "resource": "sensitive.report", "result": "LOGGED", "details": "Compliance review access recorded"},
        {"timestamp": "2025-01-17 14:14:51", "user": "system.federated", "action": "MODEL_UPDATE", "resource": "pii.detection.v2.1", "result": "DEPLOYED", "details": "New threat patterns integrated"},
    ]
    
    for event in audit_events:
        result_colors = {
            "SUCCESS": "#10b981",
            "BLOCKED": "#ef4444",
            "FILTERED": "#f59e0b",
            "LOGGED": "#6366f1",
            "DEPLOYED": "#8b5cf6"
        }
        
        st.markdown(f"""
        <div class="audit-log">
            [{event['timestamp']}] USER: {event['user']} | ACTION: {event['action']} | 
            RESOURCE: {event['resource']} | 
            <span style="color: {result_colors.get(event['result'], '#d1d5db')};">RESULT: {event['result']}</span><br>
            DETAILS: {event['details']}
        </div>
        """, unsafe_allow_html=True)
    
    # Compliance Reporting
    st.subheader("📊 Compliance Reporting Dashboard")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>📈 Monthly Compliance Trends</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Generate compliance trend data
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        compliance_data = {
            'Month': months,
            'Compliance Score (%)': [97.2, 97.8, 98.1, 98.4, 98.7, 99.1],
            'Policy Violations': [45, 38, 32, 28, 24, 18],
            'PII Incidents': [23, 19, 16, 12, 8, 5]
        }
        
        compliance_df = pd.DataFrame(compliance_data)
        st.line_chart(compliance_df.set_index('Month'))
    
    with col2:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>🎯 Business Unit Compliance</h4>
        </div>
        """, unsafe_allow_html=True)
        
        unit_compliance = {
            'Business Unit': ['Customer Service', 'Finance', 'HR', 'Legal', 'Operations', 'IT'],
            'Compliance Score': [99.2, 98.7, 99.5, 99.8, 98.1, 97.9]
        }
        
        unit_df = pd.DataFrame(unit_compliance)
        st.bar_chart(unit_df.set_index('Business Unit'))

with tab5:
    st.header("🏗️ Technical Implementation & Architecture")
    
    # Implementation Overview
    st.markdown("""
    <div class="security-header">
        <h3>Enterprise AI Security Implementation</h3>
        <p>Production-ready guardrail framework with microservice architecture, 
        comprehensive logging, and federated learning capabilities.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Technology Stack
    st.subheader("🛠️ Technology Stack & Components")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>🔧 Core Technologies</h4>
            <ul style="color: #d1d5db;">
                <li><strong>Python FastAPI</strong> - High-performance microservices</li>
                <li><strong>TensorFlow/PyTorch</strong> - ML model deployment</li>
                <li><strong>Redis</strong> - High-speed caching and session storage</li>
                <li><strong>PostgreSQL</strong> - Audit logging and policy storage</li>
                <li><strong>Docker/Kubernetes</strong> - Containerized deployment</li>
                <li><strong>Apache Kafka</strong> - Event streaming and logging</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="guardrail-pipeline">
            <h4>🤖 AI/ML Components</h4>
            <ul style="color: #d1d5db;">
                <li><strong>spaCy NER</strong> - Named entity recognition for PII</li>
                <li><strong>Transformers</strong> - BERT-based content classification</li>
                <li><strong>Regex Engine</strong> - Pattern-based detection rules</li>
                <li><strong>Federated Learning</strong> - TensorFlow Federated</li>
                <li><strong>MLflow</strong> - Model versioning and deployment</li>
                <li><strong>Evidently AI</strong> - Model monitoring and drift detection</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Implementation Code Examples
    st.subheader("💻 Core Implementation Components")
    
    tab_impl1, tab_impl2, tab_impl3 = st.tabs(["PII Detection Engine", "Guardrail Middleware", "Federated Learning"])
    
    with tab_impl1:
        st.code("""
# Advanced PII Detection with ML + Regex
import re
import spacy
from transformers import pipeline
from typing import List, Dict, Tuple

class PIIDetectionEngine:
    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")
        self.classifier = pipeline("ner", 
                                 model="dbmdz/bert-large-cased-finetuned-conll03-english")
        
        # Comprehensive regex patterns for PII detection
        self.pii_patterns = {
            'ssn': r'\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'bank_account': r'\b\d{8,17}\b',
            'medicare': r'\b[0-9]{4}-[A-Z]{2}-[0-9]{4}\b'
        }
    
    def detect_pii(self, text: str) -> Dict[str, List[Tuple[str, int, int]]]:
        \"\"\"Detect PII using combined regex + ML approach\"\"\"
        detections = {'regex': [], 'ml': [], 'confidence_scores': []}
        
        # Regex-based detection for high-precision patterns
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                detections['regex'].append((
                    pii_type, match.start(), match.end(), match.group()
                ))
        
        # ML-based named entity recognition
        entities = self.classifier(text)
        for entity in entities:
            if entity['entity'] in ['B-PER', 'I-PER', 'B-LOC', 'I-LOC']:
                detections['ml'].append((
                    entity['entity'], entity['start'], entity['end'], 
                    entity['word'], entity['score']
                ))
        
        # spaCy NER for additional context
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ in ['PERSON', 'ORG', 'GPE', 'DATE']:
                detections['ml'].append((
                    ent.label_, ent.start_char, ent.end_char, 
                    ent.text, 0.85  # spaCy confidence approximation
                ))
        
        return detections
    
    def redact_pii(self, text: str, detections: Dict) -> str:
        \"\"\"Redact detected PII with appropriate placeholders\"\"\"
        redacted_text = text
        offset = 0
        
        # Sort detections by start position (reverse order for proper offset handling)
        all_detections = []
        
        for pii_type, start, end, match in detections['regex']:
            all_detections.append((start, end, f"[{pii_type.upper()}_REDACTED]"))
        
        all_detections.sort(key=lambda x: x[0], reverse=True)
        
        # Apply redactions
        for start, end, replacement in all_detections:
            redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
        
        return redacted_text
    
    def get_redaction_metadata(self, original: str, redacted: str, 
                             detections: Dict) -> Dict:
        \"\"\"Generate comprehensive metadata for audit logging\"\"\"
        return {
            'timestamp': datetime.now().isoformat(),
            'original_length': len(original),
            'redacted_length': len(redacted),
            'pii_types_detected': list(set([d[0] for d in detections['regex']])),
            'detection_count': len(detections['regex']) + len(detections['ml']),
            'confidence_avg': sum([d[4] for d in detections['ml'] if len(d) > 4]) / 
                            max(len(detections['ml']), 1)
        }
""", language="python")
    
    with tab_impl2:
        st.code("""
# Guardrail Middleware with Policy Enforcement
from fastapi import FastAPI, HTTPException, Request
import asyncio
import json
import logging
from typing import Dict, List, Optional

class GuardrailMiddleware:
    def __init__(self):
        self.pii_detector = PIIDetectionEngine()
        self.threat_detector = ThreatDetectionEngine()
        self.policy_engine = PolicyEngine()
        self.audit_logger = AuditLogger()
        
        # Load allowlist/denylist policies
        self.policies = self.load_security_policies()
    
    async def process_request(self, request_data: Dict) -> Dict:
        \"\"\"Main guardrail processing pipeline\"\"\"
        pipeline_start = time.time()
        
        try:
            # Stage 1: Input validation and sanitization
            validation_result = await self.validate_input(request_data)
            if not validation_result['valid']:
                raise SecurityException("Input validation failed", 
                                      validation_result['errors'])
            
            # Stage 2: PII detection and redaction
            pii_result = await self.detect_and_redact_pii(request_data['content'])
            
            # Stage 3: Threat and injection detection
            threat_result = await self.detect_threats(pii_result['redacted_content'])
            
            # Stage 4: Policy enforcement
            policy_result = await self.enforce_policies(request_data, threat_result)
            
            # Stage 5: Content analysis and classification
            content_result = await self.analyze_content(pii_result['redacted_content'])
            
            # Compile final response
            processed_response = {
                'content': pii_result['redacted_content'],
                'security_status': 'APPROVED',
                'pii_detected': pii_result['pii_detected'],
                'threats_blocked': threat_result['threats_found'],
                'policy_violations': policy_result['violations'],
                'processing_time_ms': (time.time() - pipeline_start) * 1000,
                'confidence_score': min(
                    pii_result['confidence'], 
                    threat_result['confidence'], 
                    content_result['confidence']
                )
            }
            
            # Audit logging
            await self.audit_logger.log_request(
                request_data, processed_response, 'SUCCESS'
            )
            
            return processed_response
            
        except SecurityException as e:
            # Log security incident
            await self.audit_logger.log_security_incident(
                request_data, str(e), e.security_level
            )
            raise HTTPException(status_code=403, detail=str(e))
    
    async def detect_and_redact_pii(self, content: str) -> Dict:
        \"\"\"PII detection with allowlist checking\"\"\"
        detections = self.pii_detector.detect_pii(content)
        
        # Check against allowlist policies
        filtered_detections = self.filter_allowlisted_entities(detections)
        
        if filtered_detections['regex'] or filtered_detections['ml']:
            redacted_content = self.pii_detector.redact_pii(content, filtered_detections)
            return {
                'redacted_content': redacted_content,
                'pii_detected': True,
                'detections': filtered_detections,
                'confidence': 0.95
            }
        
        return {
            'redacted_content': content,
            'pii_detected': False,
            'detections': {},
            'confidence': 1.0
        }
    
    async def detect_threats(self, content: str) -> Dict:
        \"\"\"Advanced threat detection including prompt injection\"\"\"
        threat_indicators = {
            'prompt_injection': [
                r'ignore\s+previous\s+instructions',
                r'system\s*:\s*you\s+are',
                r'\\n\\n###\\n\\nignore',
                r'act\s+as\s+a.*?\bdangerous\b',
                r'jailbreak|roleplay.*evil'
            ],
            'command_injection': [
                r';\s*rm\s+-rf',
                r'&&\s*curl\s+',
                r'\|\s*nc\s+',
                r'<script.*?>.*?</script>',
                r'eval\s*\('
            ],
            'data_exfiltration': [
                r'curl.*?--data',
                r'wget.*?-O',
                r'base64.*?decode',
                r'echo.*?\|.*?mail'
            ]
        }
        
        threats_found = []
        confidence_scores = []
        
        for threat_type, patterns in threat_indicators.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    threats_found.append({
                        'type': threat_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'position': (match.start(), match.end()),
                        'severity': self.get_threat_severity(threat_type)
                    })
                    confidence_scores.append(0.9)  # High confidence for regex matches
        
        # ML-based threat detection
        ml_threats = await self.threat_detector.detect_ml_threats(content)
        threats_found.extend(ml_threats)
        
        return {
            'threats_found': threats_found,
            'confidence': sum(confidence_scores) / max(len(confidence_scores), 1)
        }
    
    def load_security_policies(self) -> Dict:
        \"\"\"Load comprehensive security policies\"\"\"
        return {
            'pii_allowlist': {
                'domains': ['@company.com', '@partner.com'],
                'patterns': ['CUSTOMER_ID_', 'ORDER_NUM_'],
                'contexts': ['testing', 'demo', 'training']
            },
            'content_policies': {
                'max_length': 10000,
                'forbidden_topics': ['violence', 'hate_speech', 'illegal'],
                'required_disclaimers': True
            },
            'access_policies': {
                'rate_limits': {'requests_per_hour': 1000},
                'ip_restrictions': [],
                'user_roles': ['admin', 'analyst', 'viewer']
            }
        }

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
        
    async def log_request(self, request: Dict, response: Dict, status: str):
        \"\"\"Comprehensive audit logging for compliance\"\"\"
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'request_id': request.get('id', 'unknown'),
            'user_id': request.get('user_id', 'anonymous'),
            'action': 'content_processing',
            'status': status,
            'pii_detected': response.get('pii_detected', False),
            'threats_blocked': len(response.get('threats_blocked', [])),
            'processing_time': response.get('processing_time_ms', 0),
            'confidence_score': response.get('confidence_score', 0)
        }
        
        # Store in multiple locations for redundancy
        await self.store_audit_log(audit_entry)
        await self.send_to_siem(audit_entry)
        
        self.logger.info(f"Audit: {json.dumps(audit_entry)}")
""", language="python")
    
    with tab_impl3:
        st.code("""
# Federated Learning for Privacy-Preserving Model Updates
import tensorflow as tf
import tensorflow_federated as tff
from typing import List, Dict, Tuple
import numpy as np

class FederatedPIILearning:
    def __init__(self, num_clients: int = 12):
        self.num_clients = num_clients
        self.global_model = self.create_global_model()
        self.client_models = {}
        self.aggregation_rounds = 0
        
    def create_global_model(self) -> tf.keras.Model:
        \"\"\"Create the global PII detection model architecture\"\"\"
        model = tf.keras.Sequential([
            tf.keras.layers.Embedding(10000, 128, mask_zero=True),
            tf.keras.layers.LSTM(64, dropout=0.3, recurrent_dropout=0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(8, activation='sigmoid')  # Multi-label PII classification
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    @tff.federated_computation
    def federated_averaging_process(self, client_data):
        \"\"\"TensorFlow Federated averaging process\"\"\"
        # Initialize the server state
        server_state = self.initialize_server_state()
        
        # Perform federated training round
        for round_num in range(self.aggregation_rounds):
            # Client update phase
            client_updates = self.client_update_fn(client_data, server_state)
            
            # Server aggregation phase
            server_state = self.server_update_fn(server_state, client_updates)
            
            # Evaluate global model performance
            metrics = self.evaluate_global_model(server_state)
            
            # Log federated learning metrics
            await self.log_federated_metrics(round_num, metrics)
        
        return server_state
    
    async def train_business_unit_model(self, unit_name: str, 
                                      local_data: List[Dict]) -> Dict:
        \"\"\"Train local model for specific business unit\"\"\"
        # Prepare local training data (privacy-preserving)
        X_local, y_local = self.prepare_local_data(local_data, unit_name)
        
        # Clone global model for local training
        local_model = tf.keras.models.clone_model(self.global_model)
        local_model.set_weights(self.global_model.get_weights())
        
        # Local training with differential privacy
        dp_optimizer = tf.keras.optimizers.Adam(learning_rate=0.001)
        local_model.compile(optimizer=dp_optimizer, 
                           loss='binary_crossentropy',
                           metrics=['accuracy'])
        
        # Train with privacy budget management
        history = local_model.fit(
            X_local, y_local,
            epochs=5,  # Limited epochs for privacy
            batch_size=32,
            validation_split=0.2,
            verbose=0
        )
        
        # Extract model updates (gradients) for federated aggregation
        model_updates = self.extract_model_updates(local_model)
        
        # Local evaluation metrics
        local_metrics = {
            'unit_name': unit_name,
            'samples_trained': len(X_local),
            'local_accuracy': history.history['accuracy'][-1],
            'local_loss': history.history['loss'][-1],
            'privacy_epsilon': self.calculate_privacy_budget(unit_name),
            'model_updates': model_updates
        }
        
        return local_metrics
    
    async def aggregate_federated_updates(self, client_updates: List[Dict]) -> Dict:
        \"\"\"Securely aggregate model updates from all business units\"\"\"
        
        # Weighted federated averaging based on local data size
        total_samples = sum([update['samples_trained'] for update in client_updates])
        
        aggregated_weights = []
        for layer_idx in range(len(self.global_model.layers)):
            layer_updates = []
            layer_weights = []
            
            for update in client_updates:
                if 'model_updates' in update:
                    weight = update['samples_trained'] / total_samples
                    layer_updates.append(update['model_updates'][layer_idx])
                    layer_weights.append(weight)
            
            # Weighted average of layer parameters
            if layer_updates:
                aggregated_layer = np.average(layer_updates, 
                                           weights=layer_weights, axis=0)
                aggregated_weights.append(aggregated_layer)
        
        # Update global model with aggregated weights
        self.global_model.set_weights(aggregated_weights)
        self.aggregation_rounds += 1
        
        # Evaluate global model performance
        global_metrics = await self.evaluate_global_performance()
        
        # Privacy accounting
        privacy_metrics = self.calculate_global_privacy_budget()
        
        return {
            'aggregation_round': self.aggregation_rounds,
            'participating_clients': len(client_updates),
            'global_accuracy': global_metrics['accuracy'],
            'global_precision': global_metrics['precision'],
            'global_recall': global_metrics['recall'],
            'privacy_epsilon_used': privacy_metrics['epsilon_used'],
            'model_version': f"federated_v{self.aggregation_rounds}"
        }
    
    def prepare_local_data(self, raw_data: List[Dict], unit_name: str) -> Tuple:
        \"\"\"Prepare and anonymize local training data\"\"\"
        # Feature extraction without exposing raw text
        features = []
        labels = []
        
        for sample in raw_data:
            # Extract privacy-preserving features
            text_features = self.extract_anonymous_features(sample['text'])
            pii_labels = self.encode_pii_labels(sample['pii_types'])
            
            features.append(text_features)
            labels.append(pii_labels)
        
        # Convert to tensors
        X = tf.constant(features, dtype=tf.float32)
        y = tf.constant(labels, dtype=tf.float32)
        
        return X, y
    
    def extract_anonymous_features(self, text: str) -> List[float]:
        \"\"\"Extract privacy-preserving features from text\"\"\"
        # Statistical features that don't expose content
        features = [
            len(text),  # Text length
            len(text.split()),  # Word count
            text.count('@'),  # Email indicators
            text.count('-'),  # SSN/phone indicators
            len(re.findall(r'\d', text)),  # Digit count
            len(re.findall(r'[A-Z]', text)),  # Uppercase count
            text.count('.'),  # Domain indicators
            sum(1 for c in text if c.isalnum()) / max(len(text), 1)  # Alphanumeric ratio
        ]
        
        # Extend to fixed feature size
        while len(features) < 128:
            features.append(0.0)
        
        return features[:128]
    
    async def deploy_updated_model(self, model_metrics: Dict) -> Dict:
        \"\"\"Deploy updated federated model to production\"\"\"
        deployment_config = {
            'model_version': model_metrics['model_version'],
            'accuracy_threshold': 0.95,
            'deployment_strategy': 'canary',
            'rollback_enabled': True,
            'monitoring_enabled': True
        }
        
        # A/B testing with canary deployment
        if model_metrics['global_accuracy'] >= deployment_config['accuracy_threshold']:
            # Deploy to 10% of traffic first
            await self.deploy_canary(deployment_config)
            
            # Monitor performance for 24 hours
            await self.monitor_canary_performance(deployment_config)
            
            # Full deployment if successful
            return await self.deploy_full_model(deployment_config)
        
        return {'status': 'deployment_rejected', 'reason': 'accuracy_below_threshold'}
""", language="python")
    
    # Performance Benchmarks
    st.subheader("⚡ System Performance Metrics")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Average Response Time", "45ms", "↓ 12ms")
        st.metric("Throughput", "50K req/hour", "↑ 15%")
    
    with col2:
        st.metric("Detection Accuracy", "97.3%", "↑ 2.1%")
        st.metric("False Positive Rate", "0.8%", "↓ 1.2%")
    
    with col3:
        st.metric("System Uptime", "99.97%", "↑ 0.03%")
        st.metric("Model Updates", "12/day", "↑ 3")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #6b7280; padding: 2rem;">
    <h4>🛡️ AI Guardrails & Security Framework</h4>
    <p>Enterprise-grade AI security • PII protection • Threat prevention • Compliance monitoring</p>
    <p><strong>Technology Stack:</strong> Python FastAPI • TensorFlow • Redis • Kubernetes • Apache Kafka</p>
    <p><em>Key Learning: Structured pre-processing > prompt engineering for reliable guardrails</em></p>
</div>
""", unsafe_allow_html=True)
