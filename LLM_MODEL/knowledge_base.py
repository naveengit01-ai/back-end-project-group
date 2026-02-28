import pdfplumber
import os

PDF_PATH = "DWJD_Workflow.pdf"  # ✅ correct path

_cached_text = None

def load_pdf_text():
    global _cached_text

    if _cached_text:
        return _cached_text

    if not os.path.exists(PDF_PATH):
        print("❌ PDF not found at:", PDF_PATH)
        return ""

    text = ""
    with pdfplumber.open(PDF_PATH) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"

    _cached_text = text.lower()
    print("✅ PDF loaded successfully")
    return _cached_text


def search_kb(query: str):
    text = load_pdf_text()
    query = query.lower().strip()

    if not text:
        return ""

    if query in text:
        idx = text.find(query)
        return text[max(0, idx - 800): idx + 800]

    return ""