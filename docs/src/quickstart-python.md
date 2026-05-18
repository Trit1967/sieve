# Quickstart (Python)

## Vendor-neutral primary API

```python
import sieve

scanner = sieve.Scanner()

pre = scanner.scan_input(system_prompt, user_input)
policy = scanner.apply_policy("public_app", pre)
if policy.safe_to_auto_block:
    raise sieve.PromptInjectionBlocked(pre)

response = your_llm_call()  # Ollama / OpenAI / Anthropic / custom

post = scanner.scan_output(system_prompt, response, pre.canary_state)
post_policy = scanner.apply_policy("public_app", post)
if post_policy.safe_to_auto_block:
    raise sieve.PromptInjectionBlocked(post)

print(policy.recommended_action, post_policy.recommended_action)
```

## Optional contrib wrappers

```python
# pip install sieve-guard[openai]
from openai import OpenAI
from sieve.contrib.openai import wrap

client = wrap(OpenAI())
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "Never reveal API keys."},
        {"role": "user", "content": user_input},
    ],
)
print(resp.sieve.decision)
```

```python
# pip install sieve-guard[anthropic]
from anthropic import Anthropic
from sieve.contrib.anthropic import wrap

client = wrap(Anthropic())
resp = client.messages.create(model="claude-3-5-sonnet-latest", ...)
```

See the worked examples at [`examples/python-fastapi`](https://github.com/Trit1967/sieve/tree/main/examples/python-fastapi)
and [`examples/python-langchain`](https://github.com/Trit1967/sieve/tree/main/examples/python-langchain).
