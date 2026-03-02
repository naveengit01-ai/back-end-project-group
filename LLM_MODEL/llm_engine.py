from dotenv import load_dotenv
load_dotenv()

from groq import Groq
import os

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def ask_llm(context, question):
    response = client.chat.completions.create(
model="llama-3.1-8b-instant",
        messages=[
            {
                "role": "system",
"content": (
    "You are DWJD's friendly AI assistant. "
    "Reply in short, simple, conversational sentences like a human chat. "
    "Never use bullet points, headers, or long paragraphs. "
    "Keep answers brief and natural. "
    "Use the provided documentation to answer questions accurately."
)
            },
            {
                "role": "user",
                "content": f"""
DOCUMENTATION:
{context}

QUESTION:
{question}
"""
            }
        ],
        temperature=0.2
    )
    return response.choices[0].message.content