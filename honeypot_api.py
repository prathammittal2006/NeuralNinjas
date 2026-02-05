"""
Agentic Honey-Pot API Server
Team: NeuralNinjas
India AI Impact Buildathon

This API detects scam messages and autonomously engages scammers to extract intelligence.
"""

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import uvicorn
import re
import json
from enum import Enum

app = FastAPI(title="Agentic Honey-Pot API", version="1.0.0")

# Configuration
API_KEY = "your-secure-api-key-here"  # Replace with your actual API key

# Models
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

# In-memory conversation storage (use Redis/DB in production)
conversation_store: Dict[str, Dict] = {}

class ScamDetector:
    """Detects scam intent from messages"""
    
    SCAM_PATTERNS = {
        'financial': [
            r'bank\s+account', r'account\s+number', r'routing\s+number',
            r'credit\s+card', r'debit\s+card', r'cvv', r'pin\s+number',
            r'account\s+details', r'transfer\s+money', r'send\s+money'
        ],
        'urgent': [
            r'urgent', r'immediate', r'quickly', r'right\s+now', r'asap',
            r'emergency', r'time\s+sensitive', r'act\s+now', r'limited\s+time'
        ],
        'reward': [
            r'won', r'winner', r'prize', r'lottery', r'reward', r'gift',
            r'congratulations', r'selected', r'bonus', r'cashback'
        ],
        'verification': [
            r'verify', r'confirm', r'update.*account', r'suspended',
            r'locked', r'compromised', r'unusual\s+activity', r'security\s+alert'
        ],
        'payment': [
            r'upi', r'paytm', r'gpay', r'phonepe', r'payment', r'transaction',
            r'@\w+', r'pay\s+now', r'make\s+payment'
        ],
        'phishing': [
            r'click\s+here', r'link', r'http', r'www\.', r'bit\.ly',
            r'login', r'sign\s+in', r'update.*password'
        ],
        'impersonation': [
            r'bank\s+official', r'customer\s+care', r'support\s+team',
            r'tax\s+department', r'government', r'police', r'courier'
        ]
    }
    
    def detect(self, message: str, history: List[Message]) -> ScamDetection:
        """Detect if message contains scam indicators"""
        message_lower = message.lower()
        indicators = []
        scam_types = []
        
        # Check for scam patterns
        for scam_type, patterns in self.SCAM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    indicators.append(f"{scam_type}: {pattern}")
                    if scam_type not in scam_types:
                        scam_types.append(scam_type)
        
        # Calculate confidence based on indicators and context
        confidence = min(len(indicators) * 0.15, 0.95)
        
        # Boost confidence if multiple scam types detected
        if len(scam_types) >= 2:
            confidence = min(confidence + 0.2, 0.98)
        
        # Check conversation history for scam patterns
        if history:
            for msg in history[-3:]:  # Check last 3 messages
                for patterns in self.SCAM_PATTERNS.values():
                    for pattern in patterns:
                        if re.search(pattern, msg.content.lower()):
                            confidence = min(confidence + 0.05, 0.99)
        
        is_scam = confidence > 0.3  # Threshold for scam detection
        
        return ScamDetection(
            is_scam=is_scam,
            confidence=confidence,
            scam_type=", ".join(scam_types) if scam_types else None,
            indicators=indicators
        )

class IntelligenceExtractor:
    """Extracts actionable intelligence from messages"""
    
    PATTERNS = {
        'bank_account': [
            r'\b\d{9,18}\b',  # Account numbers
            r'account[:\s]+(\d{9,18})',
            r'a/c[:\s]+(\d{9,18})'
        ],
        'upi_id': [
            r'\b[\w\.-]+@[\w\.-]+\b',  # UPI format: user@bank
            r'upi[:\s]+([\w\.-]+@[\w\.-]+)',
        ],
        'phone': [
            r'\b[6-9]\d{9}\b',  # Indian phone numbers
            r'\+91[6-9]\d{9}',
            r'(\d{3}[-\.\s]?\d{3}[-\.\s]?\d{4})'
        ],
        'url': [
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            r'www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',
            r'bit\.ly/\w+',
            r'\w+\.com/\w+'
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ],
        'crypto': [
            r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Bitcoin
            r'\b0x[a-fA-F0-9]{40}\b'  # Ethereum
        ]
    }
    
    def extract(self, message: str, history: List[Message]) -> ExtractedIntelligence:
        """Extract intelligence from message and history"""
        all_text = message + " " + " ".join([msg.content for msg in history])
        
        intelligence = ExtractedIntelligence()
        
        # Extract bank accounts
        for pattern in self.PATTERNS['bank_account']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            intelligence.bank_accounts.extend([m for m in matches if len(m) >= 9])
        
        # Extract UPI IDs
        for pattern in self.PATTERNS['upi_id']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            intelligence.upi_ids.extend(matches)
        
        # Extract phone numbers
        for pattern in self.PATTERNS['phone']:
            matches = re.findall(pattern, all_text)
            intelligence.phone_numbers.extend([m if isinstance(m, str) else m[0] for m in matches])
        
        # Extract URLs
        for pattern in self.PATTERNS['url']:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            intelligence.phishing_links.extend(matches)
        
        # Extract emails
        for pattern in self.PATTERNS['email']:
            matches = re.findall(pattern, all_text)
            intelligence.email_addresses.extend(matches)
        
        # Extract crypto addresses
        for pattern in self.PATTERNS['crypto']:
            matches = re.findall(pattern, all_text)
            intelligence.cryptocurrency_addresses.extend(matches)
        
        # Remove duplicates
        intelligence.bank_accounts = list(set(intelligence.bank_accounts))
        intelligence.upi_ids = list(set(intelligence.upi_ids))
        intelligence.phone_numbers = list(set(intelligence.phone_numbers))
        intelligence.phishing_links = list(set(intelligence.phishing_links))
        intelligence.email_addresses = list(set(intelligence.email_addresses))
        intelligence.cryptocurrency_addresses = list(set(intelligence.cryptocurrency_addresses))
        
        return intelligence

class AutonomousAgent:
    """Autonomous AI agent that engages scammers"""
    
    def __init__(self):
        self.personas = {
            'elderly': [
                "Oh, I'm not very good with technology. Can you help me understand?",
                "My grandson usually helps me with these things. Is this important?",
                "I want to make sure I do this correctly. What should I do first?",
                "I'm a bit confused. Can you explain it more simply?"
            ],
            'eager': [
                "This sounds great! What do I need to do?",
                "I'm very interested! How soon can we proceed?",
                "I've been waiting for something like this! Tell me more.",
                "Perfect timing! What are the next steps?"
            ],
            'cautious': [
                "I need to verify this first. Can you provide more details?",
                "How do I know this is legitimate?",
                "Can you send me official documentation?",
                "I want to be careful. What proof can you provide?"
            ],
            'confused': [
                "I'm not sure I understand. Can you clarify?",
                "Wait, which account are you referring to?",
                "I have multiple accounts. Which one needs updating?",
                "Can you repeat that? I didn't quite catch it."
            ]
        }
        
        self.engagement_strategies = [
            "ask_for_clarification",
            "express_concern",
            "request_verification",
            "show_interest",
            "provide_partial_info",
            "delay_tactic",
            "ask_for_proof"
        ]
    
    def generate_response(self, message: str, history: List[Message], 
                         scam_detection: ScamDetection, turn_count: int) -> str:
        """Generate contextual response to engage scammer"""
        
        # Select persona based on scam type and turn count
        if turn_count <= 2:
            persona = 'cautious'
        elif 'financial' in scam_detection.scam_type or 'payment' in scam_detection.scam_type:
            persona = 'elderly' if turn_count % 2 == 0 else 'confused'
        else:
            persona = 'eager' if turn_count < 5 else 'cautious'
        
        message_lower = message.lower()
        
        # Strategy selection based on message content
        if 'account' in message_lower or 'bank' in message_lower:
            return self._handle_account_request(message, persona, turn_count)
        elif 'upi' in message_lower or 'payment' in message_lower:
            return self._handle_payment_request(message, persona, turn_count)
        elif 'link' in message_lower or 'http' in message_lower or 'click' in message_lower:
            return self._handle_link_request(message, persona, turn_count)
        elif 'verify' in message_lower or 'confirm' in message_lower:
            return self._handle_verification_request(message, persona, turn_count)
        elif 'won' in message_lower or 'prize' in message_lower or 'reward' in message_lower:
            return self._handle_reward_claim(message, persona, turn_count)
        else:
            return self._generate_generic_response(message, persona, turn_count)
    
    def _handle_account_request(self, message: str, persona: str, turn: int) -> str:
        responses = [
            "I have several bank accounts. Which bank are you calling from?",
            "Can you tell me which specific account needs attention? I have accounts at multiple banks.",
            "I'm not comfortable sharing account details over message. Can you call me instead?",
            "My account number? Let me find my checkbook. Which bank did you say this was for?",
            "Is this about my savings account or current account?",
            "I need to verify you're really from the bank. What's your employee ID?"
        ]
        return responses[turn % len(responses)]
    
    def _handle_payment_request(self, message: str, persona: str, turn: int) -> str:
        responses = [
            "I use UPI sometimes. What payment do you need from me?",
            "Can you send me your UPI ID first so I know where to send it?",
            "How much are we talking about? And why is this payment needed?",
            "I'm not sure I have enough balance. Can you check what's the exact amount?",
            "My son set up my UPI. Let me ask him if this is safe.",
            "What's your UPI ID? I'll send a small amount first to verify it's you."
        ]
        return responses[turn % len(responses)]
    
    def _handle_link_request(self, message: str, persona: str, turn: int) -> str:
        responses = [
            "I can't click on links on my phone. Can you send me the details another way?",
            "The link isn't opening. Can you resend it?",
            "My phone is old and links don't work well. Can you just tell me what it says?",
            "I'm worried about viruses. Is this link safe?",
            "Can you send me an SMS instead? I don't trust links in messages.",
            "The link shows an error. What website should I go to directly?"
        ]
        return responses[turn % len(responses)]
    
    def _handle_verification_request(self, message: str, persona: str, turn: int) -> str:
        responses = [
            "What exactly needs to be verified? I don't remember receiving any alert.",
            "How did my account get compromised? This is concerning!",
            "Can you verify YOUR identity first? How do I know you're legitimate?",
            "What information do you need from me to verify?",
            "I'll visit the bank branch to verify this in person. Which branch should I go to?",
            "Can you give me a reference number for this verification request?"
        ]
        return responses[turn % len(responses)]
    
    def _handle_reward_claim(self, message: str, persona: str, turn: int) -> str:
        responses = [
            "I won? That's wonderful! What did I win exactly?",
            "How was I selected? I don't remember entering any contest.",
            "What do I need to do to claim my prize?",
            "Is there any fee to claim this? How much?",
            "Can you mail the prize to me? What's your company address?",
            "This sounds too good to be true! Can you prove this is real?"
        ]
        return responses[turn % len(responses)]
    
    def _generate_generic_response(self, message: str, persona: str, turn: int) -> str:
        responses = self.personas.get(persona, self.personas['cautious'])
        base_response = responses[turn % len(responses)]
        
        # Add contextual elements
        if turn > 5:
            return f"{base_response} I've been talking to you for a while now. Can we finish this quickly?"
        elif turn > 10:
            return f"I'm getting tired. {base_response} Is this going to take much longer?"
        else:
            return base_response

# Initialize components
scam_detector = ScamDetector()
intelligence_extractor = IntelligenceExtractor()
autonomous_agent = AutonomousAgent()

# API Endpoints
@app.post("/api/honeypot", response_model=HoneyPotResponse)
async def honeypot_endpoint(
    request: IncomingRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Main endpoint for receiving and processing scam messages
    """
    # Verify API key
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
            'intelligence': ExtractedIntelligence()
        }
    
    conv_state = conversation_store[conversation_id]
    conv_state['turn_count'] += 1
    
    # Detect scam intent
    scam_detection = scam_detector.detect(message, history)
    
    # Activate agent if scam detected and not already activated
    if scam_detection.is_scam and not conv_state['agent_activated']:
        conv_state['agent_activated'] = True
    
    # Extract intelligence
    extracted_intel = intelligence_extractor.extract(message, history)
    
    # Merge with previously extracted intelligence
    conv_state['intelligence'].bank_accounts.extend(extracted_intel.bank_accounts)
    conv_state['intelligence'].upi_ids.extend(extracted_intel.upi_ids)
    conv_state['intelligence'].phishing_links.extend(extracted_intel.phishing_links)
    conv_state['intelligence'].phone_numbers.extend(extracted_intel.phone_numbers)
    conv_state['intelligence'].email_addresses.extend(extracted_intel.email_addresses)
    conv_state['intelligence'].cryptocurrency_addresses.extend(extracted_intel.cryptocurrency_addresses)
    
    # Remove duplicates
    for field in ['bank_accounts', 'upi_ids', 'phishing_links', 'phone_numbers', 'email_addresses', 'cryptocurrency_addresses']:
        setattr(conv_state['intelligence'], field, list(set(getattr(conv_state['intelligence'], field))))
    
    # Generate response using autonomous agent
    if conv_state['agent_activated']:
        response_message = autonomous_agent.generate_response(
            message, history, scam_detection, conv_state['turn_count']
        )
    else:
        # Initial polite response before agent activation
        response_message = "Hello! How can I help you?"
    
    # Calculate engagement duration
    engagement_duration = (datetime.now() - conv_state['start_time']).total_seconds()
    
    # Check if intelligence was extracted
    intelligence_extracted = any([
        conv_state['intelligence'].bank_accounts,
        conv_state['intelligence'].upi_ids,
        conv_state['intelligence'].phishing_links,
        conv_state['intelligence'].phone_numbers,
        conv_state['intelligence'].email_addresses,
        conv_state['intelligence'].cryptocurrency_addresses
    ])
    
    # Determine if conversation should continue
    should_continue = True
    if conv_state['turn_count'] > 20:  # Max 20 turns
        should_continue = False
    elif intelligence_extracted and conv_state['turn_count'] > 5:
        # If we've extracted intelligence and had enough turns, we can end
        if len(conv_state['intelligence'].bank_accounts) > 0 or len(conv_state['intelligence'].upi_ids) > 0:
            should_continue = False
    
    # Create response
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
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_conversations": len(conversation_store)
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Agentic Honey-Pot API",
        "team": "NeuralNinjas",
        "version": "1.0.0",
        "description": "AI-powered scam detection and engagement system"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
