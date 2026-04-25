import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

_client = None

def _get_client():
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError(
                "GROQ_API_KEY is not set. "
                "Create a .env file with GROQ_API_KEY=your_key_here"
            )
        _client = Groq(api_key=api_key)
    return _client

def call_llm(prompt, system_role="You are a helpful assistant.", max_retries=3):
    """
    Calls Groq LLM with a retry mechanism for robustness.
    """
    import time
    
    last_error = ""
    for attempt in range(max_retries):
        try:
            client = _get_client()
            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_role},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.2,
                max_tokens=4096,
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            last_error = str(e)
            if "rate_limit" in last_error.lower() or "overloaded" in last_error.lower():
                wait_time = (attempt + 1) * 2  # 2s, 4s, 6s
                time.sleep(wait_time)
                continue
            break
            
    return f"Error calling Groq API: {last_error}"
