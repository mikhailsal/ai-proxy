from pydantic import BaseModel, ConfigDict, field_validator
from typing import List, Dict, Any, Optional, Union

# Based on https://platform.openai.com/docs/api-reference/chat/create


class ChatMessage(BaseModel):
    role: str
    content: Union[str, List[Any]]

    @field_validator("content")
    @classmethod
    def validate_content(cls, v):
        # Convert list format to string for backward compatibility
        if isinstance(v, list):
            # Extract text from list of content objects
            text_parts = []
            for item in v:
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    # For now, ignore non-text content like images
                else:
                    text_parts.append(str(item))
            return " ".join(text_parts)
        return v


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    n: Optional[int] = None
    stream: Optional[bool] = False
    stop: Optional[List[str]] = None
    max_tokens: Optional[int] = None
    presence_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    logit_bias: Optional[Dict[str, float]] = None
    user: Optional[str] = None

    # Allow any other fields to be passed through
    model_config = ConfigDict(extra="allow")


# Based on https://platform.openai.com/docs/api-reference/chat/object


class Choice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: Optional[str] = None


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[Choice]
    usage: Usage


# Streaming models
class DeltaChoice(BaseModel):
    index: int
    delta: Dict[str, Any]  # Can contain role, content, etc.
    finish_reason: Optional[str] = None


class ChatCompletionStreamResponse(BaseModel):
    id: str
    object: str = "chat.completion.chunk"
    created: int
    model: str
    choices: List[DeltaChoice]
