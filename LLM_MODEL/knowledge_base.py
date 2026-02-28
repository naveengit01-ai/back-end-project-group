import pdfplumber
import os

PDF_PATH = os.path.join(os.path.dirname(__file__), "DWJD_Workflow.pdf")

_cached_text = None

def load_pdf():
    global _cached_text
    if _cached_text:
        return _cached_text

    text = ""
    with pdfplumber.open(PDF_PATH) as pdf:
        for page in pdf.pages:
            text += page.extract_text() + "\n"

    _cached_text = text
    return text


def get_full_kb():
    return load_pdf()


def search_kb(query: str):
    text = load_pdf()
    keywords = query.lower().split()

    score = sum(1 for k in keywords if k in text.lower())

    # 🔹 Very loose threshold (important)
    if score >= 1:
        return text

    return None