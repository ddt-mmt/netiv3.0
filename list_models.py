import google.generativeai as genai
import os

api_key = os.environ.get("GEMINI_API_KEY") # Or replace with a dummy key for listing models
if not api_key:
    api_key = "YOUR_DUMMY_API_KEY" # Use a dummy key if not set

genai.configure(api_key=api_key)

for m in genai.list_models():
    if "generateContent" in m.supported_generation_methods:
        print(m.name)