import os

TXT_PATH = os.path.join(os.path.dirname(__file__), "knowledge.txt")

_cached_text = None

def load_txt():
    global _cached_text
    if _cached_text:
        return _cached_text

    with open(TXT_PATH, "r", encoding="utf-8") as f:
        _cached_text = f.read()

    return _cached_text


def get_full_kb():
    return load_txt()


def search_kb(query: str):
    text = load_txt()
    keywords = query.lower().split()

    score = sum(1 for k in keywords if k in text.lower())

    if score >= 1:
        return text

    return None