from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.language_models.chat_models import BaseChatModel

from src.config.core import LLMConfig

load_dotenv(override=True)

_SUPPORTED_MODELS = {"gpt-4o-mini", "gpt-4o"}


def get_chat_model(
    model_name: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    *,
    llm_config: LLMConfig | None = None,
) -> BaseChatModel:
    cfg = llm_config or LLMConfig()

    model = model_name or cfg.model
    temp = temperature if temperature is not None else cfg.temperature
    tokens = max_tokens or cfg.max_tokens

    if model not in _SUPPORTED_MODELS:
        raise ValueError(f"Unsupported model {model!r}. Choose from {_SUPPORTED_MODELS}")

    return ChatOpenAI(
        model=model,
        temperature=temp,
        max_tokens=tokens,
        seed=cfg.seed,
        top_p=cfg.top_p,
    )
