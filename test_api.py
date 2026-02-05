"""
Test script for Agentic Honey-Pot API
Team: NeuralNinjas
"""

import requests
import json
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/api/honeypot"
API_KEY = "your-secure-api-key-here"  # Match with your API key

def test_scam_conversation():
    """Test a complete scam conversation flow"""
    
    conversation_id = f"test_conv_{datetime.now().timestamp()}"
    conversation_history = []
    
    # Simulated scam messages
    scam_messages = [
        "Hello! Congratulations! You have won a prize of Rs. 50,000 from our lottery!",
        "To claim your prize, you need to verify your bank account details.",
        "Please provide your bank account number and UPI ID for immediate transfer.",
        "We need this information urgently. The offer expires in 24 hours!",
        "You can also click this link to claim: http://fake-lottery-scam.com/claim",
        "For faster processing, please share your account number now.",
    ]
    
    print("=" * 80)
    print("AGENTIC HONEY-POT TEST - SCAM DETECTION AND ENGAGEMENT")
    print("=" * 80)
    print()
    
    for i, message in enumerate(scam_messages, 1):
        print(f"\n--- Turn {i} ---")
        print(f"Scammer: {message}")
        
        # Prepare request
        payload = {
            "conversation_id": conversation_id,
            "message": message,
            "conversation_history": conversation_history,
            "metadata": {
                "source": "test_simulation",
                "turn": i
            }
        }
        
        headers = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json"
        }
        
        # Make API request
        try:
            response = requests.post(API_URL, json=payload, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            
            # Display results
            print(f"\nAgent Response: {result['response_message']}")
            print(f"\nScam Detection:")
            print(f"  - Is Scam: {result['scam_detection']['is_scam']}")
            print(f"  - Confidence: {result['scam_detection']['confidence']:.2%}")
            print(f"  - Type: {result['scam_detection']['scam_type']}")
            print(f"  - Indicators: {len(result['scam_detection']['indicators'])}")
            
            print(f"\nExtracted Intelligence:")
            intel = result['extracted_intelligence']
            print(f"  - Bank Accounts: {intel['bank_accounts']}")
            print(f"  - UPI IDs: {intel['upi_ids']}")
            print(f"  - Phishing Links: {intel['phishing_links']}")
            print(f"  - Phone Numbers: {intel['phone_numbers']}")
            
            print(f"\nEngagement Metrics:")
            metrics = result['engagement_metrics']
            print(f"  - Turns: {metrics['conversation_turns']}")
            print(f"  - Duration: {metrics['engagement_duration_seconds']:.1f}s")
            print(f"  - Agent Activated: {metrics['agent_activated']}")
            print(f"  - Intelligence Extracted: {metrics['intelligence_extracted']}")
            
            print(f"\nShould Continue: {result['should_continue']}")
            
            # Update conversation history
            conversation_history.append({
                "role": "user",
                "content": message,
                "timestamp": datetime.now().isoformat()
            })
            conversation_history.append({
                "role": "assistant",
                "content": result['response_message'],
                "timestamp": result['timestamp']
            })
            
            # Stop if conversation should not continue
            if not result['should_continue']:
                print("\n" + "=" * 80)
                print("CONVERSATION ENDED BY SYSTEM")
                print("=" * 80)
                break
                
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            break
    
    print("\n" + "=" * 80)
    print("TEST COMPLETED")
    print("=" * 80)

def test_legitimate_message():
    """Test with a legitimate message"""
    
    print("\n\n")
    print("=" * 80)
    print("TESTING LEGITIMATE MESSAGE (Should NOT trigger scam detection)")
    print("=" * 80)
    
    conversation_id = f"test_legit_{datetime.now().timestamp()}"
    message = "Hello, I'm interested in learning more about your products."
    
    payload = {
        "conversation_id": conversation_id,
        "message": message,
        "conversation_history": []
    }
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        print(f"\nMessage: {message}")
        print(f"Response: {result['response_message']}")
        print(f"Is Scam: {result['scam_detection']['is_scam']}")
        print(f"Confidence: {result['scam_detection']['confidence']:.2%}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def test_health_endpoint():
    """Test health check endpoint"""
    
    print("\n\n")
    print("=" * 80)
    print("TESTING HEALTH ENDPOINT")
    print("=" * 80)
    
    try:
        response = requests.get("http://localhost:8000/health")
        response.raise_for_status()
        result = response.json()
        
        print(f"\nHealth Status: {result['status']}")
        print(f"Active Conversations: {result['active_conversations']}")
        print(f"Timestamp: {result['timestamp']}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Starting Agentic Honey-Pot API Tests")
    print("Make sure the API server is running on http://localhost:8000")
    print()
    
    # Test health endpoint first
    test_health_endpoint()
    
    # Test with scam conversation
    test_scam_conversation()
    
    # Test with legitimate message
    test_legitimate_message()
    
    print("\n\nAll tests completed!")
