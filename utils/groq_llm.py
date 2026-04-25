"""
Groq LLM client with retry, configurable model, and exponential back-off.
"""

import logging
import os
import time

from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# Streamlit Cloud: pull secrets into env if not already set
try:
    import streamlit as _st
    if "GROQ_API_KEY" in _st.secrets and not os.getenv("GROQ_API_KEY"):
        os.environ["GROQ_API_KEY"] = _st.secrets["GROQ_API_KEY"]
    if "GROQ_MODEL" in _st.secrets and not os.getenv("GROQ_MODEL"):
        os.environ["GROQ_MODEL"] = _st.secrets["GROQ_MODEL"]
except Exception:
    pass

logger = logging.getLogger(__name__)

# Model can be overridden via env var — no need to touch source code.
DEFAULT_MODEL = "llama-3.3-70b-versatile"
FALLBACK_MODEL = "llama-3.1-8b-instant"

_client: Groq | None = None


def _get_client() -> Groq:
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


def call_llm(
    prompt: str,
    system_role: str = "You are a helpful assistant.",
    max_retries: int = 3,
    model: str | None = None,
) -> str:
    """
    Call Groq LLM with exponential back-off on rate-limit / overload errors.
    Falls back to FALLBACK_MODEL if the primary model is unavailable.

    Returns the response string, or an error string prefixed with
    'Error calling Groq API:' so callers can detect failures.
    """
    primary = model or os.getenv("GROQ_MODEL", DEFAULT_MODEL)
    models_to_try = [primary]
    if primary != FALLBACK_MODEL:
        models_to_try.append(FALLBACK_MODEL)

    last_error = ""

    for current_model in models_to_try:
        for attempt in range(max_retries):
            try:
                client = _get_client()
                response = client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_role},
                        {"role": "user", "content": prompt},
                    ],
                    model=current_model,
                    temperature=0.2,
                    max_tokens=4096,
                )
                return response.choices[0].message.content

            except Exception as exc:
                last_error = str(exc)
                lower = last_error.lower()

                if "rate_limit" in lower or "overloaded" in lower or "529" in lower:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    logger.warning(
                        "Rate limit / overload on %s (attempt %d/%d). "
                        "Waiting %ds. Error: %s",
                        current_model, attempt + 1, max_retries, wait, last_error,
                    )
                    time.sleep(wait)
                    continue

                # Non-retryable error — try next model
                logger.error(
                    "Non-retryable error on model %s: %s", current_model, last_error
                )
                break

        logger.warning("Exhausted retries for model %s.", current_model)

    return f"Error calling Groq API: {last_error}"
