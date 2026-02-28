from fastapi import FastAPI
from pydantic import BaseModel
from knowledge_base import search_kb
from llm_engine import ask_llm

app = FastAPI(title="DWJD LLM Service")

class ChatRequest(BaseModel):
    user: dict
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    try:
        message = req.message.strip().lower()

        # 1️⃣ Search PDF
        kb_context = search_kb(message)
        if kb_context:
            return {
                "reply": ask_llm(kb_context, message)
            }

        # 2️⃣ Fallback
        return {
            "reply": ask_llm(
                "DWJD is a donation and job assistance platform.",
                message
            )
        }

    except Exception as e:
        print("❌ ERROR:", str(e))
        return {
            "reply": "I'm having trouble answering that right now 🙂"
        }
@app.get("/debug/pdf")
def debug_pdf():
    from knowledge_base import load_pdf_text
    text = load_pdf_text()
    return {
        "loaded": bool(text),
        "length": len(text)
    }