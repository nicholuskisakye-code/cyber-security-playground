
from PIL import Image
def extract_metadata(file_path):
    img = Image.open(file_path)
    try:
        info = img._getexif() or {}
        return {str(k): str(v) for k,v in info.items()}
    except Exception:
        return {}
