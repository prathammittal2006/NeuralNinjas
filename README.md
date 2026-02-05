# Agentic Honey-Pot System
## Team: NeuralNinjas - India AI Impact Buildathon

### Overview
An AI-powered Agentic Honey-Pot system that detects scam messages and autonomously engages scammers to extract actionable intelligence such as bank account details, UPI IDs, and phishing links.

---

## Features

### 1. **Scam Detection Engine**
- Multi-pattern recognition for various scam types
- Confidence scoring system
- Context-aware detection using conversation history
- Detects: financial scams, phishing, impersonation, reward scams, verification scams

### 2. **Autonomous AI Agent**
- Multiple personas (elderly, eager, cautious, confused)
- Context-aware response generation
- Strategic engagement to maximize intelligence extraction
- Natural conversation flow to avoid detection

### 3. **Intelligence Extraction**
- Bank account numbers
- UPI IDs
- Phishing links/URLs
- Phone numbers
- Email addresses
- Cryptocurrency addresses

### 4. **Engagement Metrics**
- Conversation turn tracking
- Engagement duration monitoring
- Intelligence extraction success rate
- Agent activation tracking

---

## Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or download the project files**

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure API Key**
Edit the `API_KEY` variable in `honeypot_api.py`:
```python
API_KEY = "your-secure-api-key-here"
```

Or use environment variables:
```bash
cp .env.example .env
# Edit .env and set your API_KEY
```

4. **Run the server**
```bash
python honeypot_api.py
```

The API will start on `http://localhost:8000`

5. **Test the API**
```bash
# In a new terminal
python test_api.py
```

---

## API Documentation

### Endpoint: POST `/api/honeypot`

**Headers:**
```
X-API-Key: your-secure-api-key-here
Content-Type: application/json
```

**Request Body:**
```json
{
  "conversation_id": "unique-conversation-id",
  "message": "Hello! You have won a prize...",
  "conversation_history": [
    {
      "role": "user",
      "content": "Previous message",
      "timestamp": "2024-02-05T10:00:00"
    }
  ],
  "metadata": {
    "source": "whatsapp",
    "phone": "+91XXXXXXXXXX"
  }
}
```

**Response:**
```json
{
  "conversation_id": "unique-conversation-id",
  "response_message": "I'm interested! What do I need to do?",
  "scam_detection": {
    "is_scam": true,
    "confidence": 0.85,
    "scam_type": "reward, financial",
    "indicators": [
      "reward: won",
      "reward: prize",
      "urgent: immediately"
    ]
  },
  "extracted_intelligence": {
    "bank_accounts": ["1234567890"],
    "upi_ids": ["scammer@paytm"],
    "phishing_links": ["http://fake-site.com"],
    "phone_numbers": ["+91XXXXXXXXXX"],
    "email_addresses": ["scammer@email.com"],
    "cryptocurrency_addresses": []
  },
  "engagement_metrics": {
    "conversation_turns": 5,
    "engagement_duration_seconds": 45.2,
    "intelligence_extracted": true,
    "agent_activated": true
  },
  "should_continue": true,
  "timestamp": "2024-02-05T10:05:00"
}
```

---

## Deployment

### Local Development
```bash
python honeypot_api.py
```

### Production Deployment

#### Option 1: Using Uvicorn directly
```bash
uvicorn honeypot_api:app --host 0.0.0.0 --port 8000 --workers 4
```

#### Option 2: Using Gunicorn (recommended for production)
```bash
pip install gunicorn
gunicorn honeypot_api:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

#### Option 3: Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot_api.py .
COPY .env .

EXPOSE 8000
CMD ["uvicorn", "honeypot_api:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:
```bash
docker build -t honeypot-api .
docker run -p 8000:8000 honeypot-api
```

### Cloud Deployment Options

#### Render.com
1. Push code to GitHub
2. Connect repository to Render
3. Configure as Web Service
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `uvicorn honeypot_api:app --host 0.0.0.0 --port $PORT`

#### Railway.app
1. Push code to GitHub
2. Connect repository to Railway
3. Railway auto-detects Python
4. Add environment variables
5. Deploy

#### Heroku
```bash
# Create Procfile
echo "web: uvicorn honeypot_api:app --host 0.0.0.0 --port \$PORT" > Procfile

# Deploy
heroku create honeypot-neuralninja
git push heroku main
```

#### AWS EC2
```bash
# SSH into EC2 instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Install dependencies
sudo apt update
sudo apt install python3-pip
pip3 install -r requirements.txt

# Run with screen/tmux
screen -S honeypot
python3 honeypot_api.py
# Detach: Ctrl+A, D
```

---

## Architecture

### Components

1. **ScamDetector**
   - Pattern-based detection
   - Multi-category classification
   - Confidence scoring
   - Historical context analysis

2. **IntelligenceExtractor**
   - Regex-based extraction
   - Multi-pattern matching
   - Deduplication
   - Historical aggregation

3. **AutonomousAgent**
   - Persona management
   - Strategy selection
   - Context-aware responses
   - Engagement optimization

4. **Conversation Manager**
   - State management
   - Turn tracking
   - Duration monitoring
   - Intelligence aggregation

### Flow Diagram
```
Incoming Message
      ↓
Scam Detection
      ↓
   Is Scam? ──No──> Polite Response
      ↓
     Yes
      ↓
Activate Agent
      ↓
Generate Strategic Response
      ↓
Extract Intelligence
      ↓
Update Metrics
      ↓
Return Response
```

---

## Security Considerations

1. **API Key Authentication**: All requests require valid API key
2. **Rate Limiting**: Implement rate limiting in production
3. **Input Validation**: All inputs are validated using Pydantic
4. **No Data Persistence**: Conversations stored in-memory (use Redis in production)
5. **HTTPS**: Always use HTTPS in production
6. **CORS**: Configure CORS appropriately for your use case

---

## Performance Optimization

### For Production:

1. **Use Redis for conversation storage**
```python
import redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)
```

2. **Implement caching**
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def detect_scam_cached(message: str) -> ScamDetection:
    # Cache scam detection results
    pass
```

3. **Add request queuing**
```python
from fastapi_queue import QueueWorker
```

4. **Monitor with logging**
```python
import logging
logging.basicConfig(level=logging.INFO)
```

---

## Monitoring and Metrics

### Key Metrics to Track:

1. **Detection Accuracy**: % of correctly identified scams
2. **Engagement Duration**: Average conversation length
3. **Intelligence Extraction Rate**: % of conversations extracting actionable intelligence
4. **False Positive Rate**: % of legitimate messages flagged as scams
5. **API Response Time**: Average latency

### Logging
```python
import logging

logger = logging.getLogger("honeypot")
logger.info(f"Scam detected with confidence {confidence}")
```

---

## Testing

### Unit Tests
```bash
# Run tests
python test_api.py
```

### Load Testing
```bash
# Install locust
pip install locust

# Run load test
locust -f load_test.py
```

---

## Troubleshooting

### Common Issues

1. **Port already in use**
```bash
# Find process using port 8000
lsof -i :8000
# Kill process
kill -9 <PID>
```

2. **Module not found**
```bash
pip install -r requirements.txt
```

3. **API key authentication failing**
- Check header name: `X-API-Key`
- Verify API key matches in both client and server

---

## Future Enhancements

1. **Machine Learning Integration**
   - Train custom ML models for scam detection
   - Use NLP for better context understanding
   - Implement sentiment analysis

2. **Advanced Intelligence**
   - Image analysis for QR codes and screenshots
   - Voice call support
   - Multi-language support

3. **Reporting Dashboard**
   - Real-time analytics
   - Intelligence visualization
   - Scam pattern analysis

4. **Integration**
   - WhatsApp Business API
   - Telegram Bot API
   - SMS gateway integration

---

## License
MIT License - Free for educational and commercial use

## Team
**NeuralNinjas** - India AI Impact Buildathon 2025

## Support
For issues or questions, please create an issue in the repository or contact the team.

---

## API Reference Quick Guide

### Health Check
```bash
curl http://localhost:8000/health
```

### Test Scam Detection
```bash
curl -X POST http://localhost:8000/api/honeypot \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "conversation_id": "test-123",
    "message": "You won a lottery! Send your bank account.",
    "conversation_history": []
  }'
```

### Get API Documentation
```bash
# Visit in browser
http://localhost:8000/docs
```

---

**Built with ❤️ by NeuralNinjas for a safer digital India**
