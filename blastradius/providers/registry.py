"""Provider registry — all supported LLM providers (OpenAI-compatible).

The model lists are **suggestions only**: the client never validates model
names, so any model ID the provider accepts (including brand-new ones) can be
used — pass it via ``BLASTRADIUS_MODEL``, the CLI ``set`` command, or an
explicit ``model=`` argument. Unknown models are forwarded to the provider,
which decides.
"""

PROVIDER_REGISTRY = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "models": [
            "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4.1", "gpt-4.1-mini",
            "gpt-4.1-nano", "gpt-4", "gpt-4-32k", "o1", "o1-mini", "o3", "o3-mini",
            "chatgpt-4o-latest", "gpt-3.5-turbo",
            # current lineup (2026)
            "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5",
            "gpt-realtime-2.1", "gpt-realtime-2.1-mini", "gpt-realtime-2",
            "gpt-image-2", "gpt-4o-transcribe",
        ],
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "key_env": "ANTHROPIC_API_KEY",
        "models": [
            "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5",
            "claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest", "claude-3-opus-latest", "claude-3-haiku-latest",
            "claude-3-7-sonnet-20250219", "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022", "claude-3-opus-20240229",
            # current lineup (2026)
            "claude-fable-5", "claude-opus-5", "claude-sonnet-5",
            "claude-opus-4-8", "claude-opus-4-7", "claude-sonnet-4-5", "claude-opus-4-5",
        ],
        "extra_headers": {"anthropic-version": "2023-06-01"},
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "key_env": "DEEPSEEK_API_KEY",
        "models": [
            "deepseek-chat", "deepseek-reasoner", "deepseek-coder",
            "deepseek-v3", "deepseek-r1",
            # current lineup (2026)
            "deepseek-v4-flash", "deepseek-v4-pro",
        ],
    },
    "opencode_zen": {
        "base_url": "https://opencode.ai/zen/go/v1",
        "key_env": "OPENCODE_API_KEY",
        "models": [
            "deepseek-v4-flash", "claude-sonnet-4-6", "gpt-4o",
            # current lineup (2026): cross-provider core models on Zen
            "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5",
            "claude-opus-4-5", "claude-sonnet-4-5", "gemini-3.6-flash",
            "grok-4.5", "qwen3.7-max", "deepseek-v4-pro", "minimax-m3",
            "glm-5.2", "kimi-k3",
        ],
    },
    "opencode_go": {
        "base_url": "https://opencode.ai/go/v1",
        "key_env": "OPENCODE_API_KEY",
        "models": [
            "deepseek-v4-flash",
            "deepseek-v4-pro", "mimo-v2.5", "mimo-v2.5-pro", "grok-4.5",
            "gpt-5.6-luna", "glm-5.2", "glm-5.1", "kimi-k3",
            "kimi-k2.7-code", "kimi-k2.6", "minimax-m3", "qwen3.8-max",
            "qwen3.7-max", "qwen3.7-plus", "hy3",
        ],
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "models": [
            "auto", "openai/gpt-4o", "openai/gpt-4o-mini",
            "anthropic/claude-3.5-sonnet", "anthropic/claude-3.7-sonnet",
            "deepseek/deepseek-chat", "meta-llama/llama-3.1-405b-instruct",
            "mistralai/mistral-large", "google/gemini-2.0-flash",
            # current lineup (2026)
            "qwen/qwen3.8-max", "deepseek/deepseek-v4-flash",
            "anthropic/claude-opus-5", "google/gemini-3.6-flash",
            "moonshotai/kimi-k3", "openai/gpt-5.6-sol", "openai/gpt-5.6-terra",
            "openai/gpt-5.6-luna", "x-ai/grok-4.5", "google/gemini-3.5-flash-lite",
        ],
    },
    "qwen": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "key_env": "QWEN_API_KEY",
        "models": [
            "qwen-max", "qwen-plus", "qwen-turbo", "qwen2.5-coder-32b-instruct",
            "qwen2.5-72b-instruct", "qwen2.5-32b-instruct", "qwen2.5-14b-instruct",
            "qwen2.5-7b-instruct", "qwen3-235b-a22b", "qwen3-32b", "qwen3-14b",
        ],
    },
    "kimi": {
        "base_url": "https://api.moonshot.cn/v1",
        "key_env": "KIMI_API_KEY",
        "models": [
            "moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k",
            "moonshot-v1-auto", "kimi-latest", "kimi-k2-0905-preview",
        ],
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
        "models": [
            "llama-3.1-70b-versatile", "llama-3.1-8b-instant",
            "llama-3.3-70b-versatile", "llama-3.2-90b-vision-preview",
            "llama-3.2-11b-vision-preview", "llama-3.2-3b-preview",
            "llama-3.2-1b-preview", "mixtral-8x7b-32768", "gemma2-9b-it",
            "deepseek-r1-distill-llama-70b",
            # current lineup (2026): namespaced IDs
            "openai/gpt-oss-120b", "openai/gpt-oss-20b", "openai/gpt-oss-safeguard-20b",
            "qwen/qwen3.6-27b", "minimaxai/minimax-m2.7", "groq/compound",
            "groq/compound-mini", "whisper-large-v3", "whisper-large-v3-turbo",
        ],
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "key_env": "TOGETHER_API_KEY",
        "models": [
            "meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B",
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen2.5-72B-Instruct-Turbo", "deepseek-ai/DeepSeek-V3",
            "google/gemma-2-27b-it",
        ],
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "key_env": "MISTRAL_API_KEY",
        "models": [
            "mistral-large-latest", "mistral-medium", "mistral-small-latest",
            "codestral-latest", "mistral-nemo", "open-mistral-nemo",
            "pixtral-large-latest", "mistral-7b-instruct",
            # current lineup (2026): <name>-<yymm> API IDs
            "mistral-medium-2604", "mistral-small-2603", "mistral-large-2512",
            "codestral-2508", "mistral-embed", "mistral-moderation-2603",
            "labs-leanstral-2603",
        ],
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "key_env": "GOOGLE_API_KEY",
        "models": [
            "gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-2.5-pro-preview",
            "gemini-2.5-flash", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro",
            # current lineup (2026)
            "gemini-3-pro", "gemini-3-flash", "gemini-3.6-flash",
            "gemini-2.5-pro", "gemini-2.5-flash-lite", "gemini-embedding-001",
        ],
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "key_env": "XAI_API_KEY",
        "models": [
            "grok-2", "grok-2-mini", "grok-beta", "grok-2-1212", "grok-2-mini-1212",
            # current lineup (2026)
            "grok-4.5", "grok-4.3", "grok-4.20-0309-reasoning",
            "grok-4.20-0309-non-reasoning", "grok-4.20-multi-agent-0309",
            "grok-build-0.1",
        ],
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "key_env": None,
        "models": [
            "llama3.1", "llama3.2", "mistral", "codellama", "deepseek-coder-v2",
            "qwen2.5", "gemma2", "phi3", "llama2", "deepseek-r1",
            # current lineup (2026)
            "llama3.3", "gemma3", "gemma4", "qwen3", "qwen2.5-coder",
        ],
        "api_key": "ollama",
    },
    "lmstudio": {
        "base_url": "http://localhost:1234/v1",
        "key_env": None,
        "models": ["local-model"],
        "api_key": "lm-studio",
    },
}

# Auto-selection priority (best first); local providers come last.
PROVIDER_PRIORITY = [
    "opencode_zen", "opencode_go", "deepseek", "openai", "anthropic",
    "openrouter", "groq", "together", "mistral", "google", "xai",
    "qwen", "kimi", "ollama", "lmstudio",
]
