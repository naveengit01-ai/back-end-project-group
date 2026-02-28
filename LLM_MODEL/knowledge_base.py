import pdfplumber

KB_TEXT = ""

def load_pdf():
    global KB_TEXT
    with pdfplumber.open("DWJD_Workflow.pdf") as pdf:
        KB_TEXT = "\n".join(page.extract_text() or "" for page in pdf.pages).lower()

load_pdf()

def search_kb(query: str):
    if "how" in query or "work" in query or "donation" in query:
        return KB_TEXT[:1500]  # limit context
    return None