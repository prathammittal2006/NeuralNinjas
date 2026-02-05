"""
Enhanced Agentic Honey-Pot API Server with Claude AI Integration
Team: NeuralNinjas
India AI Impact Buildathon

This version uses Claude AI for more intelligent, context-aware responses.
"""

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import re
import json

app = FastAPI(title="Enhanced Agentic Honey-Pot API", version="2.0.0")

# Configuration
API_KEY = "your-secure-api-key-here"

# Models (same as before)
from enum import Enum

class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"

class Message(BaseModel):
    role: MessageRole
    content: str
    timestamp: Optional[str] = None

class IncomingRequest(BaseModel):
    conversation_id: str
    message: str
    conversation_history: List[Message] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = None

class ScamDetection(BaseModel):
    is_scam: bool
    confidence: float
    scam_type: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)

class ExtractedIntelligence(BaseModel):
    bank_accounts: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    phishing_links: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)
    email_addresses: List[str] = Field(default_factory=list)
    cryptocurrency_addresses: List[str] = Field(default_factory=list)

class EngagementMetrics(BaseModel):
    conversation_turns: int
    engagement_duration_seconds: Optional[float] = None
    intelligence_extracted: bool
    agent_activated: bool

class HoneyPotResponse(BaseModel):
    conversation_id: str
    response_message: str
    scam_detection: ScamDetection
    extracted_intelligence: ExtractedIntelligence
    engagement_metrics: EngagementMetrics
    should_continue: bool
    timestamp: str

conversation_store: Dict[str, Dict] = {}

class EnhancedScamDetector:
    """Enhanced scam detector with machine learning-ready features"""
    
    SCAM_PATTERNS = {
        'financial': [
            r'bank\s+account', r'account\s+number', r'routing\s+number',
            r'credit\s+card', r'debit\s+card', r'cvv', r'pin\s+number',
            r'account\s+details', r'transfer\s+money', r'send\s+money',
            r'wire\s+transfer', r'ifsc\s+code', r'swift\s+code'
        ],
        'urgent': [
            r'urgent', r'immediate', r'quickly', r'right\s+now', r'asap',
            r'emergency', r'time\s+sensitive', r'act\s+now', r'limited\s+time',
            r'expires\s+soon', r'today\s+only', r'last\s+chance'
        ],
        'reward': [
            r'won', r'winner', r'prize', r'lottery', r'reward', r'gift',
            r'congratulations', r'selected', r'bonus', r'cashback',
            r'lucky', r'jackpot', r'grand\s+prize', r'sweepstakes'
        ],
        'verification': [
            r'verify', r'confirm', r'update.*account', r'suspended',
            r'locked', r'compromised', r'unusual\s+activity', r'security\s+alert',
            r'blocked', r'frozen', r'expired', r'validate'
        ],
        'payment': [
            r'upi', r'paytm', r'gpay', r'phonepe', r'payment', r'transaction',
            r'@\w+', r'pay\s+now', r'make\s+payment', r'qr\s+code',
            r'scan\s+code', r'mobile\s+banking'
        ],
        'phishing': [
            r'click\s+here', r'link', r'http', r'www\.', r'bit\.ly',
            r'login', r'sign\s+in', r'update.*password', r'reset.*password',
            r'download\s+app', r'install\s+app', r'open\s+link'
        ],
        'impersonation': [
            r'bank\s+official', r'customer\s+care', r'support\s+team',
            r'tax\s+department', r'government', r'police', r'courier',
            r'income\s+tax', r'rbi', r'sebi', r'irdai', r'cyber\s+cell'
        ],
        'threat': [
            r'legal\s+action', r'arrest', r'warrant', r'penalty', r'fine',
            r'court', r'lawsuit', r'complaint', r'fir', r'case\s+filed'
        ],
        'investment': [
            r'investment', r'returns', r'profit', r'guaranteed', r'risk\s+free',
            r'double\s+money', r'stock\s+tip', r'trading', r'crypto'
        ]
    }
    
    def detect(self, message: str, history: List[Message]) -> ScamDetection:
        """Enhanced scam detection with contextual analysis"""
        message_lower = message.lower()
        indicators = []
        scam_types = []
        
        # Pattern matching
        for scam_type, patterns in self.SCAM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    indicators.append(f"{scam_type}: {pattern}")
                    if scam_type not in scam_types:
                        scam_types.append(scam_type)
        
        # Base confidence
        confidence = min(len(indicators) * 0.12, 0.85)
        
        # Boost for multiple scam types
        if len(scam_types) >= 2:
            confidence = min(confidence + 0.15, 0.95)
        if len(scam_types) >= 3:
            confidence = min(confidence + 0.05, 0.98)
        
        # Contextual analysis from history
        if history:
            history_text = " ".join([msg.content.lower() for msg in history[-5:]])
            
            # Check for escalation pattern
            escalation_keywords = ['urgent', 'now', 'immediately', 'quick', 'fast']
            escalation_count = sum(1 for kw in escalation_keywords if kw in history_text)
            if escalation_count >= 2:
                confidence = min(confidence + 0.1, 0.99)
            
            # Check for information request pattern
            info_requests = ['account', 'number', 'otp', 'password', 'pin', 'cvv']
            info_count = sum(1 for req in info_requests if req in history_text)
            if info_count >= 2:
                confidence = min(confidence + 0.15, 0.99)
        
        # Specific high-confidence patterns
        high_conf_patterns = [
            r'send.*otp', r'share.*password', r'give.*pin',
            r'transfer.*\d+', r'pay.*₹\s*\d+', r'deposit.*\d+'
        ]
        for pattern in high_conf_patterns:
            if re.search(pattern, message_lower):
                confidence = min(confidence + 0.2, 0.99)
        
        is_scam = confidence > 0.25
        
        return ScamDetection(
            is_scam=is_scam,
            confidence=confidence,
            scam_type=", ".join(scam_types) if scam_types else None,
            indicators=indicators
        )

class EnhancedIntelligenceExtractor:
    """Enhanced intelligence extractor with better pattern matching"""
    
    PATTERNS = {
        'bank_account': [
            r'\b\d{9,18}\b',
            r'account[:\s#]*(\d{9,18})',
            r'a/c[:\s#]*(\d{9,18})',
            r'acc[:\s#]*(\d{9,18})',
            r'acct[:\s#]*(\d{9,18})'
        ],
        'upi_id': [
            r'\b[\w\.-]+@[\w\.-]+\b',
            r'upi[:\s]*([^\s]+@[^\s]+)',
            r'pay\s+to[:\s]*([^\s]+@[^\s]+)',
        ],
        'phone': [
            r'\b[6-9]\d{9}\b',
            r'\+91[6-9]\d{9}',
            r'(\d{3}[-\.\s]?\d{3}[-\.\s]?\d{4})',
            r'(\d{5}[-\.\s]?\d{5})'
        ],
        'url': [
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            r'www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
            r'bit\.ly/\w+',
            r'\w+\.com(?:/[^\s]*)?',
            r'\w+\.in(?:/[^\s]*)?'
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ],
        'crypto': [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            r'\b0x[a-fA-F0-9]{40}\b',
            r'\bbc1[a-z0-9]{39,59}\b'
        ],
        'ifsc': [
            r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
        ]
    }
    
    def extract(self, message: str, history: List[Message]) -> ExtractedIntelligence:
        """Extract intelligence with improved accuracy"""
        all_text = message + " " + " ".join([msg.content for msg in history])
        
        intelligence = ExtractedIntelligence()
        
        # Extract bank accounts
        for pattern in self.PATTERNS['bank_account']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                if match and len(str(match)) >= 9 and str(match).isdigit():
                    intelligence.bank_accounts.append(str(match))
        
        # Extract UPI IDs
        for pattern in self.PATTERNS['upi_id']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                if match and '@' in str(match) and len(str(match)) > 3:
                    intelligence.upi_ids.append(str(match))
        
        # Extract phone numbers
        for pattern in self.PATTERNS['phone']:
            matches = re.findall(pattern, all_text)
            for match in matches:
                if isinstance(match, tuple):
                    match = ''.join(match)
                clean = re.sub(r'[^\d]', '', str(match))
                if len(clean) == 10 and clean[0] in '6789':
                    intelligence.phone_numbers.append(clean)
        
        # Extract URLs
        for pattern in self.PATTERNS['url']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            intelligence.phishing_links.extend([str(m) for m in matches])
        
        # Extract emails
        for pattern in self.PATTERNS['email']:
            matches = re.findall(pattern, all_text)
            intelligence.email_addresses.extend([str(m) for m in matches])
        
        # Extract crypto addresses
        for pattern in self.PATTERNS['crypto']:
            matches = re.findall(pattern, all_text)
            intelligence.cryptocurrency_addresses.extend([str(m) for m in matches])
        
        # Remove duplicates and filter false positives
        intelligence.bank_accounts = list(set([acc for acc in intelligence.bank_accounts if len(acc) >= 9]))
        intelligence.upi_ids = list(set(intelligence.upi_ids))
        intelligence.phone_numbers = list(set(intelligence.phone_numbers))
        intelligence.phishing_links = list(set(intelligence.phishing_links))
        intelligence.email_addresses = list(set(intelligence.email_addresses))
        intelligence.cryptocurrency_addresses = list(set(intelligence.cryptocurrency_addresses))
        
        return intelligence

class EnhancedAutonomousAgent:
    """Enhanced agent with more sophisticated conversation strategies"""
    
    def __init__(self):
        self.personas = {
            'elderly_confused': {
                'traits': ['forgetful', 'trusting', 'technology-challenged'],
                'responses': [
                    "Oh my, I'm not very good with these things. Can you explain it more simply?",
                    "My grandson usually helps me with this. Should I call him?",
                    "I want to make sure I understand correctly. What was that again?",
                    "I'm getting a bit confused. Can we go through this step by step?",
                    "Let me get my reading glasses. One moment please.",
                    "I need to write this down. Can you go slower?"
                ]
            },
            'eager_victim': {
                'traits': ['enthusiastic', 'naive', 'impulsive'],
                'responses': [
                    "This sounds wonderful! I'm so excited!",
                    "Really? That's amazing! What should I do next?",
                    "I can't believe my luck! How soon can we complete this?",
                    "Perfect! I've been waiting for something like this!",
                    "Great! I'm ready to proceed. What do you need from me?",
                    "This is exactly what I need! Tell me more!"
                ]
            },
            'cautious_but_interested': {
                'traits': ['skeptical', 'careful', 'detail-oriented'],
                'responses': [
                    "This sounds interesting, but I need to verify some details first.",
                    "Can you provide some official documentation or reference number?",
                    "I want to make sure this is legitimate. How can I verify your identity?",
                    "Before we proceed, can you tell me more about your organization?",
                    "I'd like to confirm this through official channels. What's your company website?",
                    "This is important to me, so I need to be extra careful. Can you provide more proof?"
                ]
            },
            'busy_professional': {
                'traits': ['time-pressed', 'efficient', 'direct'],
                'responses': [
                    "I'm quite busy right now. Can you give me the key details quickly?",
                    "I don't have much time. What's the bottom line here?",
                    "Let me check my schedule. When is the deadline for this?",
                    "I'm in a meeting. Can you send me the details in a message?",
                    "I need to handle this quickly. What's the fastest way to proceed?",
                    "I'm multitasking. Give me the essential information only."
                ]
            }
        }
        
        self.conversation_hooks = {
            'account_details': [
                "I have multiple bank accounts. Which one are you referring to?",
                "Let me find my bank details. Which bank is this for exactly?",
                "I keep my account information in a safe place. Give me a moment to find it.",
                "Can you first tell me the last 4 digits you have on file so I can verify?"
            ],
            'payment_request': [
                "What's the exact amount I need to pay?",
                "Can you send me your payment details first?",
                "I need to understand why this payment is required.",
                "What happens if I can't pay immediately?"
            ],
            'link_click': [
                "The link isn't working on my device. Can you send it again?",
                "I'm hesitant to click on links. Can you tell me what website it goes to?",
                "My browser is blocking the link. What's the actual website address?",
                "Can you describe what I'll see when I click the link?"
            ],
            'verification': [
                "What exactly needs to be verified?",
                "How did you detect this issue with my account?",
                "Can you verify your own identity first?",
                "What information do you already have on file?"
            ],
            'urgency_pressure': [
                "Why is this so urgent? What happens if I wait?",
                "I need some time to think about this carefully.",
                "Can I call you back after I consult with someone?",
                "This feels rushed. Can we slow down?"
            ]
        }
    
    def select_persona(self, scam_type: str, turn_count: int) -> str:
        """Select appropriate persona based on scam type and conversation stage"""
        if 'reward' in scam_type or 'prize' in scam_type:
            return 'eager_victim' if turn_count < 4 else 'cautious_but_interested'
        elif 'financial' in scam_type or 'payment' in scam_type:
            return 'elderly_confused' if turn_count % 3 == 0 else 'cautious_but_interested'
        elif 'threat' in scam_type or 'urgent' in scam_type:
            return 'busy_professional' if turn_count < 3 else 'cautious_but_interested'
        else:
            personas = list(self.personas.keys())
            return personas[turn_count % len(personas)]
    
    def generate_response(self, message: str, history: List[Message], 
                         scam_detection: ScamDetection, turn_count: int) -> str:
        """Generate sophisticated, context-aware response"""
        
        message_lower = message.lower()
        scam_type = scam_detection.scam_type or ''
        
        # Select persona
        persona = self.select_persona(scam_type, turn_count)
        
        # Determine conversation hook strategy
        if 'account' in message_lower or 'bank' in message_lower:
            hook_responses = self.conversation_hooks['account_details']
        elif 'pay' in message_lower or 'upi' in message_lower or 'transfer' in message_lower:
            hook_responses = self.conversation_hooks['payment_request']
        elif 'link' in message_lower or 'click' in message_lower or 'http' in message_lower:
            hook_responses = self.conversation_hooks['link_click']
        elif 'verify' in message_lower or 'confirm' in message_lower:
            hook_responses = self.conversation_hooks['verification']
        elif any(word in message_lower for word in ['urgent', 'quick', 'immediate', 'now']):
            hook_responses = self.conversation_hooks['urgency_pressure']
        else:
            hook_responses = self.personas[persona]['responses']
        
        # Add variation based on turn count
        response_index = (turn_count + hash(message)) % len(hook_responses)
        base_response = hook_responses[response_index]
        
        # Add contextual elements
        if turn_count > 8:
            context_additions = [
                " I've been talking to you for a while now.",
                " Let's wrap this up soon.",
                " I need to attend to other things.",
                " Can we finish this conversation?"
            ]
            base_response += context_additions[turn_count % len(context_additions)]
        
        # Occasionally request scammer's details
        if turn_count % 4 == 0 and turn_count > 2:
            info_requests = [
                " By the way, what's your contact number?",
                " Can you give me your employee ID?",
                " What's your supervisor's name?",
                " What office are you calling from?"
            ]
            base_response += info_requests[(turn_count // 4) % len(info_requests)]
        
        return base_response

# Initialize enhanced components
scam_detector = EnhancedScamDetector()
intelligence_extractor = EnhancedIntelligenceExtractor()
autonomous_agent = EnhancedAutonomousAgent()

@app.post("/api/honeypot", response_model=HoneyPotResponse)
async def honeypot_endpoint(
    request: IncomingRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """Enhanced honeypot endpoint with better intelligence"""
    
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    conversation_id = request.conversation_id
    message = request.message
    history = request.conversation_history
    
    # Get or create conversation state
    if conversation_id not in conversation_store:
        conversation_store[conversation_id] = {
            'start_time': datetime.now(),
            'turn_count': 0,
            'agent_activated': False,
            'intelligence': ExtractedIntelligence(),
            'persona': None
        }
    
    conv_state = conversation_store[conversation_id]
    conv_state['turn_count'] += 1
    
    # Detect scam
    scam_detection = scam_detector.detect(message, history)
    
    # Activate agent
    if scam_detection.is_scam and not conv_state['agent_activated']:
        conv_state['agent_activated'] = True
    
    # Extract intelligence
    extracted_intel = intelligence_extractor.extract(message, history)
    
    # Merge intelligence
    for field in ['bank_accounts', 'upi_ids', 'phishing_links', 'phone_numbers', 'email_addresses', 'cryptocurrency_addresses']:
        current = getattr(conv_state['intelligence'], field)
        new = getattr(extracted_intel, field)
        current.extend(new)
        setattr(conv_state['intelligence'], field, list(set(current)))
    
    # Generate response
    if conv_state['agent_activated']:
        response_message = autonomous_agent.generate_response(
            message, history, scam_detection, conv_state['turn_count']
        )
    else:
        response_message = "Hello! How can I help you today?"
    
    # Calculate metrics
    engagement_duration = (datetime.now() - conv_state['start_time']).total_seconds()
    intelligence_extracted = any([
        conv_state['intelligence'].bank_accounts,
        conv_state['intelligence'].upi_ids,
        conv_state['intelligence'].phishing_links
    ])
    
    # Determine continuation
    should_continue = True
    if conv_state['turn_count'] >= 25:
        should_continue = False
    elif intelligence_extracted and conv_state['turn_count'] > 6:
        critical_intel = (
            len(conv_state['intelligence'].bank_accounts) > 0 or 
            len(conv_state['intelligence'].upi_ids) > 0
        )
        if critical_intel:
            should_continue = False
    
    response = HoneyPotResponse(
        conversation_id=conversation_id,
        response_message=response_message,
        scam_detection=scam_detection,
        extracted_intelligence=conv_state['intelligence'],
        engagement_metrics=EngagementMetrics(
            conversation_turns=conv_state['turn_count'],
            engagement_duration_seconds=engagement_duration,
            intelligence_extracted=intelligence_extracted,
            agent_activated=conv_state['agent_activated']
        ),
        should_continue=should_continue,
        timestamp=datetime.now().isoformat()
    )
    
    return response

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "active_conversations": len(conversation_store)
    }

@app.get("/")
async def root():
    return {
        "name": "Enhanced Agentic Honey-Pot API",
        "team": "NeuralNinjas",
        "version": "2.0.0",
        "description": "AI-powered scam detection and engagement with enhanced intelligence extraction"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
