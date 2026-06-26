import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

cyber_keywords = [
    "phishing", "malware", "virus", "hacking", "cyber", "security",
    "password", "attack", "ransomware", "malicious", "spyware", "scam",
    "data breach", "authentication", "encryption", "vpn"
]


def is_cyber_related(message):
    message = message.lower()
    return any(keyword in message for keyword in cyber_keywords)


def generate_chat_response(user_message):

    if not is_cyber_related(user_message):
        return "⚠️ I am a cybersecurity assistant. Please ask questions related to cybersecurity."

    try:
        # prompt = f"""
        # You are ProofPixel AI assistant.
        #
        # Answer in clean format:
        # - short paragraphs
        # - bullet points
        # - easy to read
        # - cybersecurity focused
        #
        # Question: {user_message}
        # """

        prompt = f"""
        You are ProofPixel AI assistant.

        Detect the language of the user's message.

        Reply in that language.

        If the user writes a language using English letters (romanized text),
        understand the intended language and reply in its native script.

        Examples:
        - roman Marathi → reply in Marathi script
        - roman Hindi → reply in Hindi script
        - English → reply in English script

        Answer in clean format:
        - short paragraphs
        - bullet points
        - easy to read
        - cybersecurity focused

        Question: {user_message}
        """

        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }

        data = {
            "model": "openai/gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=20
        )

        result = response.json()

        text = result["choices"][0]["message"]["content"]
        text = text.replace("*", "")
        text = text.replace("#", "")
        text = text.replace("\n", "<br>")

        return text

    except Exception as e:
        return f"Error generating response: {str(e)}"







#..........................................................................................


