from fastapi import FastAPI
from pydantic import BaseModel
from intent_router import detect_intent
from knowledge_base import search_kb
from llm_engine import ask_llm
from rule_replies import rule_reply

app = FastAPI(title="DWJD LLM Service")

class ChatRequest(BaseModel):
    user: dict
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    message = req.message.lower()
    user = req.user

    # 1️⃣ Rule-based replies
    rule = rule_reply(message, user)
    if rule:
        return {"reply": rule}

    # 2️⃣ Knowledge base (PDF)
    kb_context = search_kb(message)
    if kb_context:
        return {"reply": ask_llm(kb_context, message)}

    # 3️⃣ Fallback LLM
    return {
        "reply": ask_llm(
            "DWJD is a donation and job assistance platform.",
            message
        )
    }