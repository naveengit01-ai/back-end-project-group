from fastapi import FastAPI
from pydantic import BaseModel
from llm_engine import ask_llm
from knowledge_base import search_kb

app = FastAPI(title="DWJD LLM Service")

class ChatRequest(BaseModel):
    user: dict
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    try:
        question = req.message.lower()

        # 🔍 Search PDF knowledge base
        kb_context = search_kb(question)

        # 🧠 If PDF has relevant content, use it
        if kb_context:
            return {
                "reply": ask_llm(kb_context, question)
            }

        # 🤖 Fallback (no PDF match)
        return {
            "reply": ask_llm(
                "DWJD is a donation and job assistance platform.",
                question
            )
        }

    except Exception as e:
        print("❌ LLM ERROR:", str(e))
        return {
            "reply": "I'm having trouble answering that right now, but I can still help with login, signup, donations, and jobs 🙂"
        }
@app.get("/debug/pdf")
def debug_pdf():
    from knowledge_base import load_pdf_text
    text = load_pdf_text()
    return {
        "loaded": bool(text),
        "length": len(text)
    }