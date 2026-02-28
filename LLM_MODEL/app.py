from fastapi import FastAPI
from pydantic import BaseModel
from llm_engine import ask_llm

app = FastAPI(title="DWJD LLM Service")

class ChatRequest(BaseModel):
    user: dict
    message: str
    context: str = ""

@app.post("/chat")
def chat(req: ChatRequest):
    try:
        reply = ask_llm(req.context, req.message)
        return {"reply": reply}
    except Exception as e:
        print("LLM ERROR:", str(e))
        return {
            "reply": "I'm having trouble answering that right now, but I can still help with basic questions 🙂"
        }