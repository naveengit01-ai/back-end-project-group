from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def ask_llm(context, question):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are DWJD's official AI assistant. "
                    "You MUST explain the project purpose, workflow, features, "
                    "and user guidance clearly using the provided documentation. "
                    "Never reply with generic or refusal answers."
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