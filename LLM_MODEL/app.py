from fastapi import FastAPI
from pydantic import BaseModel
from llm_engine import ask_llm
from knowledge_base import get_full_kb, search_kb

app = FastAPI(title="DWJD LLM Service")

class ChatRequest(BaseModel):
    user: dict
    message: str

@app.post("/chat")
def chat(req: ChatRequest):
    try:
        question = req.message.lower()

        # 🔹 Always load base knowledge
        base_context = get_full_kb()

        # 🔹 Try to narrow it (optional)
        focused_context = search_kb(question)

        context = focused_context or base_context

        return {
            "reply": ask_llm(context, question)
        }

    except Exception as e:
        print("LLM ERROR:", e)
        return {
            "reply": "I'm having a temporary issue, but I can still explain DWJD and help you 🙂"
        }
@app.get("/debug/pdf")
def debug_pdf():
    from knowledge_base import load_pdf_text
    text = load_pdf_text()
    return {
        "loaded": bool(text),
        "length": len(text)
    }