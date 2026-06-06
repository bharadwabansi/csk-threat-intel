# CSK Threat Intelligence Portal

AI-powered threat intelligence portal that crawls CSK alerts,
enriches them using Groq AI, and converts to STIX 2.1 format.

## Setup
1. pip install -r requirements.txt
2. playwright install chromium
3. Add GROQ_API_KEY to .env file
4. cd backend && python main.py
5. Open frontend/index.html