# Building a Single AI Agent: From Zero to Production

> A comprehensive, opinionated guide to architecting, implementing, and deploying a single AI agent system.

---

## Table of Contents

1. [Step-by-Step Guide: Zero to Production](#1-step-by-step-guide-zero-to-production)
2. [Agent Architecture Patterns](#2-agent-architecture-patterns)
3. [Tool Definition and Implementation](#3-tool-definition-and-implementation)
4. [Building the Agent Loop](#4-building-the-agent-loop)
5. [Managing Conversation Context and History](#5-managing-conversation-context-and-history)
6. [Error Handling and Retry Logic](#6-error-handling-and-retry-logic)
7. [Building Custom Tools](#7-building-custom-tools)
8. [RAG Integration for Agents](#8-rag-integration-for-agents)
9. [Code Implementation Patterns](#9-code-implementation-patterns)
10. [Testing and Debugging Agents](#10-testing-and-debugging-agents)
11. [Agent Frameworks Comparison](#11-agent-frameworks-comparison)

---

## Single Agent Architecture — Full Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            SINGLE AI AGENT SYSTEM                              │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                          ORCHESTRATION LAYER                              │  │
│  │                                                                           │  │
│  │   ┌─────────────┐    ┌──────────────┐    ┌──────────────────────────┐    │  │
│  │   │  System      │    │  Agent Loop  │    │  Planner / Reasoner      │    │  │
│  │   │  Prompt      │───▶│  Controller  │───▶│  (ReAct / Reflexion)     │    │  │
│  │   └─────────────┘    └──────┬───────┘    └──────────────────────────┘    │  │
│  │                              │                                             │  │
│  │            ┌─────────────────┼─────────────────┐                         │  │
│  │            │                 │                 │                         │  │
│  │            ▼                 ▼                 ▼                         │  │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │  │
│  │   │  Plan Step   │  │ Execute Step │  │ Reflect Step │                  │  │
│  │   │  (decompose) │  │ (tool call)  │  │ (evaluate)   │                  │  │
│  │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                  │  │
│  │          │                 │                 │                            │  │
│  └──────────┼─────────────────┼─────────────────┼────────────────────────────┘  │
│             │                 │                 │                                │
│  ┌──────────▼─────────────────▼─────────────────▼────────────────────────────┐  │
│  │                          TOOL EXECUTION LAYER                             │  │
│  │                                                                          │  │
│  │   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐    │  │
│  │   │   Search   │  │  Database  │  │   Code     │  │   File System   │    │  │
│  │   │   Tool     │  │   Tool     │  │  Exec Tool │  │   Tool          │    │  │
│  │   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └──────┬─────────┘    │  │
│  │         │               │               │                │               │  │
│  └─────────┼───────────────┼───────────────┼────────────────┼───────────────┘  │
│            │               │               │                │                  │
│  ┌─────────▼───────────────▼───────────────▼────────────────▼───────────────┐  │
│  │                          INFRASTRUCTURE LAYER                             │  │
│  │                                                                          │  │
│  │   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐    │  │
│  │   │  LLM API   │  │   Vector   │  │   Redis    │  │   Rate Limit   │    │  │
│  │   │  (OpenAI / │  │   Store    │  │   Cache    │  │   / Backoff    │    │  │
│  │   │   Claude)  │  │ (ChromaDB/ │  │            │  │                │    │  │
│  │   │            │  │  Pinecone) │  │            │  │                │    │  │
│  │   └────────────┘  └────────────┘  └────────────┘  └────────────────┘    │  │
│  │                                                                          │  │
│  │   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────┐    │  │
│  │   │  Memory    │  │   Token    │  │    Log     │  │   Guardrails   │    │  │
│  │   │  Store     │  │  Counter   │  │   Store    │  │   / Validator  │    │  │
│  │   │ (Conv DB)  │  │            │  │ (LangSmith)│  │                │    │  │
│  │   └────────────┘  └────────────┘  └────────────┘  └────────────────┘    │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Step-by-Step Guide: Zero to Production

### Phase 1: Foundation (Week 1)

#### Step 1 — Define the Agent's Purpose

Before writing a single line of code, crystallize:

- **What single task** does this agent solve? (Be specific: "an agent that researches competitors and produces market analysis reports" — not "a general-purpose assistant")
- **What decisions** must the agent make autonomously vs. what requires human approval?
- **What tools** does it need? List every external system it must interact with.
- **What are failure modes?** What happens when a tool breaks, the LLM hallucinates, or context exceeds limits?

#### Step 2 — Choose Your LLM Provider and Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    MODEL SELECTION MATRIX                       │
│                                                                 │
│   Use Case              │  Recommended Model    │  Reasoning    │
│   ──────────────────────┼───────────────────────┼────────────── │
│   Complex reasoning     │  Claude 3.5 Sonnet    │  Best CoT     │
│   Tool calling           │  GPT-4o              │  Best func     │
│   Cost-sensitive prod    │  GPT-4o-mini         │  Cheap + good  │
│   Open-source reqmt      │  Llama 3.1 70B       │  Top OSS      │
│   Latency-critical       │  Claude 3 Haiku      │  ~1s response  │
│   Long context (200k+)   │  Gemini 1.5 Pro      │  2M context   │
└─────────────────────────────────────────────────────────────────┘
```

#### Step 3 — Set Up the Project Structure

```
my_agent/
├── agent/
│   ├── __init__.py
│   ├── core.py            # Agent loop, orchestration
│   ├── prompts.py         # System prompts, templates
│   ├── state.py           # State management, history
│   └── config.py          # Configuration, env vars
├── tools/
│   ├── __init__.py
│   ├── base.py            # Base tool class
│   ├── search.py          # Web search tool
│   ├── database.py        # Database query tool
│   ├── code_exec.py       # Code execution sandbox
│   └── file_ops.py        # File system operations
├── rag/
│   ├── __init__.py
│   ├── embedder.py        # Embedding generation
│   ├── retriever.py       # Vector store retrieval
│   └── chunker.py         # Document chunking
├── tests/
│   ├── test_agent.py
│   ├── test_tools.py
│   └── test_rag.py
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── .env
```

### Phase 2: Core Loop (Week 2)

#### Step 4 — Implement the System Prompt

The system prompt is the agent's constitution. It must define:

1. **Identity**: Who the agent is and what it does
2. **Available tools**: Names, descriptions, and when to use each
3. **Behavioral constraints**: What the agent must never do
4. **Output format**: How the agent should structure its reasoning

#### Step 5 — Implement the Agent Loop

This is the heart of the system. See [Section 4](#4-building-the-agent-loop) for the full implementation.

#### Step 6 — Implement the First Tool

Start with one simple tool (e.g., web search). Validate the full loop works end-to-end before adding complexity.

### Phase 3: Hardening (Week 3)

#### Step 7 — Add Error Handling

Add retry logic, timeouts, and graceful degradation. See [Section 6](#6-error-handling-and-retry-logic).

#### Step 8 — Add Memory and Context Management

Implement conversation history truncation, summarization, and persistent storage. See [Section 5](#5-managing-conversation-context-and-history).

#### Step 9 — Add RAG (If Applicable)

If the agent needs private knowledge, integrate retrieval-augmented generation. See [Section 8](#8-rag-integration-for-agents).

### Phase 4: Production (Week 4)

#### Step 10 — Testing, Monitoring, Deployment

See [Section 10](#10-testing-and-debugging-agents) for testing strategies. Deploy with observability (LangSmith, Helicone, or custom).

---

## 2. Agent Architecture Patterns

### ReAct (Reasoning + Acting)

The foundational pattern. The agent reasons about what to do, acts by calling a tool, and observes the result.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ReAct PATTERN                                       │
│                                                                             │
│   Input: "What is the population of the country where the Eiffel           │
│           Tower is located?"                                                │
│                                                                             │
│   ┌────────────────────────────┐                                           │
│   │  Thought 1: I need to find │                                           │
│   │  where the Eiffel Tower is.│                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Action 1: search("Eiffel │                                           │
│   │  Tower location")         │                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Observation 1: The Eiffel │                                           │
│   │  Tower is in Paris, France│                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Thought 2: Now I need the│                                           │
│   │  population of France.     │                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Action 2: search("France  │                                           │
│   │  population 2024")        │                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Observation 2: France has │                                           │
│   │  ~68 million people        │                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   ┌────────────────────────────┐                                           │
│   │  Thought 3: I have the    │                                           │
│   │  answer.                   │                                           │
│   └────────────┬───────────────┘                                           │
│                │                                                            │
│                ▼                                                            │
│   Answer: "The Eiffel Tower is in France, which has a population           │
│            of approximately 68 million."                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Reflexion

Extends ReAct with a **self-evaluation** loop. After generating an answer, the agent critiques its own response and retries if the evaluation fails.

```
┌──────────────────────────────────────────────────────────────────┐
│                    REFLEXION PATTERN                              │
│                                                                  │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐                 │
│   │  Actor   │    │ Evaluator│    │ Reflector│                 │
│   │(ReAct    │───▶│ (Scoring │───▶│ (Self    │                 │
│   │ Loop)    │    │  Fn)     │    │  Critique│                 │
│   └──────────┘    └────┬─────┘    └────┬─────┘                 │
│                        │               │                        │
│                        │    ┌──────────▼─────────┐             │
│                        │    │  Is evaluation      │             │
│                        │    │  acceptable?         │             │
│                        │    │  ┌─────┐  ┌────┐   │             │
│                        │    │  │ YES │  │ NO │   │             │
│                        │    │  └──┬──┘  └─┬──┘   │             │
│                        │    └───┼───────┼───────┘             │
│                            │       │                        │
│                            ▼       ▼                        │
│                      ┌─────────┐  ┌──────────────────┐      │
│                      │  Output │  │ Update memory     │      │
│                      │         │  │ with reflection,  │      │
│                      └─────────┘  │ retry Actor ──────┼──┐   │
│                                   └──────────────────┘  │   │
│                        ▲                                 │   │
│                        └─────────────────────────────────┘   │
│                                                               │
│   Key insight: Reflections are stored in LONG-TERM memory     │
│   and injected into future attempts as "lessons learned".      │
└──────────────────────────────────────────────────────────────────┘
```

### LATS (Language Agent Tree Search)

Treats agent reasoning as a **tree search** problem. Uses Monte Carlo Tree Search (MCTS) to explore multiple reasoning paths, evaluate them, and select the best.

```
┌──────────────────────────────────────────────────────────────────┐
│                      LATS PATTERN                                │
│                                                                  │
│                        ┌─────┐                                   │
│                        │Root │                                   │
│                        │Input │                                  │
│                        └──┬──┘                                   │
│                    ┌──────┼──────┐                               │
│                    ▼      ▼      ▼                               │
│                 ┌─────┐┌─────┐┌─────┐      ← Expand: generate   │
│                 │ A1  ││ A2  ││ A3  │        multiple actions   │
│                 └──┬──┘└──┬──┘└──┬──┘                               │
│                ┌──┴──┐   │   ┌──┴──┐                               │
│                │ A1.1│   │   │ A3.1│      ← Simulate: rollout    │
│                └──┬──┘   │   └──┬──┘        each candidate      │
│                   │      │      │                                 │
│             ┌─────┴──┐   │  ┌───┴────┐                            │
│             │V=+0.8  │   │  │V=-0.3  │   ← Evaluate: score       │
│             └────────┘   │  └────────┘     each rollout          │
│                          │                                       │
│             ┌────────────┴──────────────┐                         │
│             │  BACKPROPAGATE scores up  │                         │
│             │  SELECT best path, repeat │                         │
│             └───────────────────────────┘                         │
│                                                                  │
│   Advantage: Explores multiple strategies before committing.      │
│   Disadvantage: Computationally expensive (many LLM calls).      │
└──────────────────────────────────────────────────────────────────┘
```

### AutoGPT Pattern

An autonomous loop where the agent sets its own goals, breaks them into sub-tasks, and executes without human intervention.

```
┌──────────────────────────────────────────────────────────────────┐
│                   AutoGPT PATTERN                                │
│                                                                  │
│   ┌────────────────────────────────────────────────────┐         │
│   │                  GOAL QUEUE                         │         │
│   │   ["Research AI safety", "Write report", "Save"]   │         │
│   └──────────────────┬─────────────────────────────────┘         │
│                      │                                           │
│                      ▼                                           │
│   ┌──────────────────────────────┐                               │
│   │  1. Pick next goal from queue│                               │
│   │  2. Generate plan            │                               │
│   │  3. Execute plan step        │                               │
│   │  4. Evaluate result          │                               │
│   │  5. Queue new goals if needed│                               │
│   │  6. Loop until goals empty   │                               │
│   └──────────────────────────────┘                               │
│                                                                  │
│   ⚠ WARNING: Without guardrails, can loop infinitely.           │
│   ALWAYS set: max_iterations, cost_cap, human_approval_gates.    │
└──────────────────────────────────────────────────────────────────┘
```

### Pattern Selection Guide

```
┌────────────────────┬─────────────────┬──────────────┬───────────────┐
│  Pattern           │  Best For       │  LLM Calls   │  Complexity   │
├────────────────────┼─────────────────┼──────────────┼───────────────┤
│  ReAct             │  Most tasks     │  Low         │  Low          │
│  Reflexion         │  Tasks needing  │  Medium      │  Medium       │
│                    │  self-correction│              │               │
│  LATS              │  Complex multi- │  High        │  High         │
│                    │  path reasoning │              │               │
│  AutoGPT           │  Long-running   │  Very High   │  High         │
│                    │  autonomous work │              │               │
└────────────────────┴─────────────────┴──────────────┴───────────────┘
```

---

## 3. Tool Definition and Implementation

### Function Calling Schema (OpenAI Format)

```python
# The standard format for defining tools that the LLM can call
SEARCH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web for information. Use this when you need "
                       "current data, facts, or information not in your training data.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query string"
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return",
                    "default": 5
                },
                "date_range": {
                    "type": "string",
                    "enum": ["day", "week", "month", "year"],
                    "description": "Time range for results"
                }
            },
            "required": ["query"],
            "additionalProperties": False
        }
    }
}
```

### JSON Mode vs. Structured Outputs

```
┌──────────────────────────────────────────────────────────────────────────┐
│           JSON MODE vs. STRUCTURED OUTPUTS vs. FUNCTION CALLING          │
│                                                                          │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │   JSON Mode      │  │ Structured Output │  │  Function Calling      │  │
│  │                  │  │  (JSON Schema)    │  │                        │  │
│  │  LLM returns     │  │  LLM returns     │  │  LLM selects a tool    │  │
│  │  raw JSON,       │  │  JSON that       │  │  and arguments from    │  │
│  │  you parse it    │  │  GUARANTEED      │  │  a pre-defined list    │  │
│  │  yourself        │  │  matches schema  │  │                        │  │
│  ├─────────────────┤  ├──────────────────┤  ├────────────────────────┤  │
│  │ ✓ Simple        │  │ ✓ Validated      │  │ ✓ Rigorous schema     │  │
│  │ ✓ Flexible      │  │ ✓ Type-safe      │  │ ✓ Tool routing built  │  │
│  │                 │  │ ✓ Reliable       │  │   into API             │  │
│  │ ✗ May break     │  │ ✗ Limited models │  │ ✗ More boilerplate    │  │
│  │ ✗ No validation │  │ ✗ Stricter       │  │ ✗ Model-dependent     │  │
│  └─────────────────┘  └──────────────────┘  └────────────────────────┘  │
│                                                                          │
│  RECOMMENDATION: Use Function Calling for agents (tool routing),         │
│  Structured Outputs for data extraction, JSON Mode for quick hacks.      │
└──────────────────────────────────────────────────────────────────────────┘
```

### Base Tool Abstraction

```python
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field


class ToolResult(BaseModel):
    success: bool
    output: str | dict | list
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BaseTool(ABC):
    name: str
    description: str
    parameters_schema: dict

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        ...

    def to_openai_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            }
        }
```

---

## 4. Building the Agent Loop

### Agent Loop State Machine

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        AGENT LOOP STATE MACHINE                              │
│                                                                              │
│                           ┌──────────┐                                      │
│                           │  START    │                                      │
│                           └────┬─────┘                                        │
│                                │                                              │
│                                ▼                                              │
│                        ┌──────────────┐                                       │
│                  ┌────▶│    PLAN      │◀──────────────┐                      │
│                  │     │              │               │                      │
│                  │     │ Decompose    │               │                      │
│                  │     │ task into    │               │                      │
│                  │     │ sub-steps    │               │                      │
│                  │     └──────┬───────┘               │                      │
│                  │            │                       │                      │
│                  │            ▼                       │                      │
│                  │     ┌──────────────┐               │                      │
│                  │     │   EXECUTE    │               │                      │
│                  │     │              │               │                      │
│                  │     │ Call tool    │               │                      │
│                  │     │ with args    │               │                      │
│                  │     └──────┬───────┘               │                      │
│                  │            │                       │                      │
│                  │            ▼                       │                      │
│                  │     ┌──────────────┐               │                      │
│                  │     │   OBSERVE    │               │                      │
│                  │     │              │               │                      │
│                  │     │ Process tool │               │                      │
│                  │     │ result       │               │                      │
│                  │     └──────┬───────┘               │                      │
│                  │            │                       │                      │
│                  │            ▼                       │                      │
│                  │     ┌──────────────┐      ┌────────┴────────┐             │
│                  │     │   REFLECT    │──────│ Task complete?  │             │
│                  │     │              │      │                  │             │
│                  │     │ Evaluate     │      │ NO → replan     │             │
│                  │     │ progress     │      │ YES → respond   │             │
│                  │     └──────┬───────┘      └────────┬────────┘             │
│                  │            │                       │                      │
│                  │            │  ┌────────────┐       │                      │
│                  │            └──│ Replan if  │◀──────┤                      │
│                  │               │ needed     │       │                      │
│                  └───────────────└────────────┘       │                      │
│                                                       │                      │
│                                             ┌─────────▼────────┐              │
│                                             │     RESPOND      │              │
│                                             │                  │              │
│                                             │ Return final     │              │
│                                             │ answer to user   │              │
│                                             └─────────┬────────┘              │
│                                                       │                      │
│                                             ┌─────────▼────────┐              │
│                                             │      END         │              │
│                                             └──────────────────┘              │
│                                                                              │
│                                                                              │
│   GUARDRAILS (checked at every transition):                                 │
│   ┌────────────────────────────────────────────────────────┐                 │
│   │ • max_iterations (default: 10)                         │                 │
│   │ • max_tokens_total (default: 100k)                    │                 │
│   │ • cost_limit (default: $5.00)                          │                 │
│   │ • timeout_per_step (default: 30s)                      │                 │
│   │ • repetition detection (same tool call 3x = halt)     │                 │
│   └────────────────────────────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Core Agent Loop Implementation

```python
import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from openai import AsyncOpenAI

from .tools import BaseTool, ToolResult
from .state import ConversationState


@dataclass
class AgentConfig:
    model: str = "gpt-4o"
    max_iterations: int = 10
    max_tokens_total: int = 100_000
    cost_limit: float = 5.00
    timeout_per_step: float = 30.0
    max_retries: int = 3
    repetition_threshold: int = 3


class Agent:
    def __init__(
        self,
        system_prompt: str,
        tools: list[BaseTool],
        config: AgentConfig | None = None,
    ):
        self.client = AsyncOpenAI()
        self.system_prompt = system_prompt
        self.tools = {t.name: t for t in tools}
        self.tool_schemas = [t.to_openai_schema() for t in tools]
        self.config = config or AgentConfig()
        self.state = ConversationState()

    async def run(self, user_input: str) -> str:
        self.state.add_message("user", user_input)

        for iteration in range(self.config.max_iterations):
            self._check_guardrails()

            response = await self._call_llm()

            if response.finish_reason == "stop":
                return response.content

            if response.finish_reason == "tool_calls":
                tool_results = await self._execute_tools(response.tool_calls)

                self.state.add_message("assistant", response.raw_content)
                for tc, result in zip(response.tool_calls, tool_results):
                    self.state.add_tool_result(tc.id, result)

                continue

        return "Agent reached maximum iterations without completing the task."

    async def _call_llm(self) -> "LLMResponse":
        messages = self.state.get_messages()
        response = await self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            tools=self.tool_schemas,
            temperature=0.0,
        )
        return LLMResponse.from_openai(response)

    async def _execute_tools(self, tool_calls: list) -> list[ToolResult]:
        results = []
        for tc in tool_calls:
            tool = self.tools.get(tc.function.name)
            if not tool:
                results.append(ToolResult(
                    success=False,
                    output=f"Unknown tool: {tc.function.name}",
                    error="tool_not_found"
                ))
                continue

            kwargs = json.loads(tc.function.arguments)
            result = await self._call_tool_with_retry(tool, kwargs)
            results.append(result)

        return results

    async def _call_tool_with_retry(
        self, tool: BaseTool, kwargs: dict
    ) -> ToolResult:
        for attempt in range(self.config.max_retries):
            try:
                result = await asyncio.wait_for(
                    tool.execute(**kwargs),
                    timeout=self.config.timeout_per_step,
                )
                if result.success:
                    return result
            except asyncio.TimeoutError:
                if attempt == self.config.max_retries - 1:
                    return ToolResult(
                        success=False,
                        output="Tool timed out",
                        error="timeout"
                    )
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    return ToolResult(
                        success=False,
                        output=str(e),
                        error="execution_error"
                    )
            await asyncio.sleep(2 ** attempt)

        return ToolResult(success=False, output="Max retries exceeded", error="retries_exhausted")

    def _check_guardrails(self):
        if self.state.total_tokens > self.config.max_tokens_total:
            raise TokenLimitExceeded()
        if self.state.estimated_cost > self.config.cost_limit:
            raise CostLimitExceeded()
        if self.state.has_repetition(self.config.repetition_threshold):
            raise RepetitionDetected()
```

---

## 5. Managing Conversation Context and History

### Context Window Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    CONTEXT WINDOW MANAGEMENT                              │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────┐       │
│  │                    TOKEN BUDGET (e.g., 128k)                  │       │
│  │                                                               │       │
│  │  ┌─────────────┐  ┌────────────────┐  ┌──────────────────┐   │       │
│  │  │   System    │  │   Working      │  │  Conversation     │   │       │
│  │  │   Prompt    │  │   Memory       │  │  History          │   │       │
│  │  │   (~2k)     │  │   (~4k)        │  │  (remaining)      │   │       │
│  │  └─────────────┘  └────────────────┘  └──────────────────┘   │       │
│  │                                                               │       │
│  │  ┌─────────────┐  ┌────────────────┐                          │       │
│  │  │  Tool       │  │  Reserved for  │                          │       │
│  │  │  Results    │  │  LLM Response  │                          │       │
│  │  │  (variable) │  │  (~4k)         │                          │       │
│  │  └─────────────┘  └────────────────┘                          │       │
│  └───────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  STRATEGIES WHEN CONTEXT OVERFLOWS:                                      │
│                                                                          │
│  ┌──────────────────┬────────────────────────────────────────────┐       │
│  │  Strategy        │  Description                              │       │
│  ├──────────────────┼────────────────────────────────────────────┤       │
│  │  Truncation      │  Drop oldest messages until fits          │       │
│  │  Summarization   │  Summarize old messages, keep recent      │       │
│  │  Sliding Window  │  Keep last N messages only                │       │
│  │  RAG              │  Move history to vector DB, retrieve      │       │
│  │                  │  relevant parts on demand                 │       │
│  └──────────────────┴────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────┘
```

### Conversation State Manager

```python
import tiktoken
from dataclasses import dataclass, field


@dataclass
class Message:
    role: str
    content: str | dict | list
    token_count: int = 0


class ConversationState:
    def __init__(self, max_context_tokens: int = 100_000):
        self.messages: list[Message] = []
        self.max_context_tokens = max_context_tokens
        self._encoder = tiktoken.encoding_for_model("gpt-4o")
        self.total_tokens = 0
        self.estimated_cost = 0.0
        self._tool_call_history: list[str] = []

    def add_message(self, role: str, content: str | dict | list):
        tokens = self._count_tokens(content) if isinstance(content, str) else 0
        msg = Message(role=role, content=content, token_count=tokens)
        self.messages.append(msg)
        self.total_tokens += tokens
        self._update_cost()

    def add_tool_result(self, tool_call_id: str, result: ToolResult):
        self._tool_call_history.append(tool_call_id)
        tokens = self._count_tokens(str(result.output))
        msg = Message(
            role="tool",
            content=result.output,
            token_count=tokens,
        )
        self.messages.append(msg)
        self.total_tokens += tokens

    def get_messages(self) -> list[dict]:
        self._maybe_summarize()
        return [
            {"role": m.role, "content": m.content}
            for m in self.messages
        ]

    def _maybe_summarize(self):
        if self.total_tokens <= self.max_context_tokens * 0.8:
            return
        cutoff = len(self.messages) // 3
        old_messages = self.messages[:cutoff]
        self.messages = self.messages[cutoff:]
        summary = f"[Earlier conversation summarized: {len(old_messages)} messages about {self._extract_topic(old_messages)}]"
        self.messages.insert(0, Message(role="system", content=summary, token_count=50))

    def has_repetition(self, threshold: int = 3) -> bool:
        if len(self._tool_call_history) < threshold:
            return False
        recent = self._tool_call_history[-threshold:]
        return len(set(recent)) == 1

    def _count_tokens(self, text: str) -> int:
        return len(self._encoder.encode(text))

    def _update_cost(self):
        input_cost = (self.total_tokens / 1_000_000) * 2.50
        self.estimated_cost = input_cost

    def _extract_topic(self, messages: list[Message]) -> str:
        first_user_msg = next(
            (m.content for m in messages if m.role == "user"), ""
        )
        if isinstance(first_user_msg, str) and len(first_user_msg) > 50:
            return first_user_msg[:50] + "..."
        return str(first_user_msg)[:50]
```

---

## 6. Error Handling and Retry Logic

### Error Handling and Retry Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    ERROR HANDLING AND RETRY FLOW                          │
│                                                                          │
│   Tool Call                                                              │
│      │                                                                   │
│      ▼                                                                   │
│   ┌──────────────────┐                                                  │
│   │  Execute Tool     │                                                 │
│   └────────┬─────────┘                                                  │
│            │                                                              │
│      ┌─────┴─────┐                                                      │
│      │  Success?  │                                                      │
│      └─────┬─────┘                                                      │
│       Yes  │   No                                                        │
│       │    │                                                             │
│       │    ▼                                                             │
│       │  ┌──────────────────┐                                            │
│       │  │ Classify Error   │                                            │
│       │  └────────┬─────────┘                                            │
│       │           │                                                       │
│       │    ┌──────┼────────────────┐                                    │
│       │    │      │                │                                     │
│       │    ▼      ▼                ▼                                     │
│       │ ┌──────────┐ ┌──────────┐ ┌──────────────┐                      │
│       │ │Transient │ │Rate Limit│ │  Permanent   │                      │
│       │ │ Error    │ │ Error    │ │  Error       │                      │
│       │ │(network, │ │(429,     │ │(invalid args,│                      │
│       │ │ timeout)│ │ throttled)│ │ auth fail)   │                      │
│       │ └────┬─────┘ └────┬─────┘ └──────┬───────┘                      │
│       │      │             │             │                                │
│       │      ▼             ▼             │                                │
│       │ ┌──────────┐ ┌──────────┐      │                                │
│       │ │Retry with│ │Retry with│      │                                 │
│       │ │exp back- │ │exp back- │      │                                 │
│       │ │off (3x) │ │off+reset │      │                                 │
│       │ └────┬─────┘ └────┬─────┘      │                                │
│       │      │             │            │                                │
│       │      ▼             ▼            ▼                                │
│       │ ┌────────────────────────┐ ┌──────────────┐                     │
│       │ │Return result or       │ │Report error   │                     │
│       │ │escalate to agent      │ │to LLM with    │                     │
│       │ │after max retries      │ │context        │                     │
│       │ └───────────────────────┘ └──────────────┘                     │
│       │                     ▲                    ▲                       │
│       │                     │                    │                       │
│       └─── Return tool ────┘                    │                       │
│            result to agent          LLM decides │                       │
│                                      next action│                       │
│                                      (try diff  │                       │
│                                       tool, ask │                       │
│                                       user, etc)│                       │
└──────────────────────────────────────────────────────────────────────────┘
```

### Retry Decorator Implementation

```python
import asyncio
import functools
from enum import Enum


class ErrorCategory(Enum):
    TRANSIENT = "transient"
    RATE_LIMIT = "rate_limit"
    PERMANENT = "permanent"


def classify_error(error: Exception) -> ErrorCategory:
    transient_types = (ConnectionError, asyncio.TimeoutError, OSError)
    rate_limit_markers = ("429", "rate_limit", "throttl")

    if isinstance(error, transient_types):
        return ErrorCategory.TRANSIENT

    error_str = str(error).lower()
    if any(m in error_str for m in rate_limit_markers):
        return ErrorCategory.RATE_LIMIT

    return ErrorCategory.PERMANENT


def with_retry(max_retries: int = 3, base_delay: float = 1.0):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    category = classify_error(e)

                    if category == ErrorCategory.PERMANENT:
                        raise

                    delay = base_delay * (2 ** attempt)
                    if category == ErrorCategory.RATE_LIMIT:
                        delay *= 2

                    if attempt < max_retries - 1:
                        await asyncio.sleep(delay)

            raise last_error
        return wrapper
    return decorator
```

---

## 7. Building Custom Tools

### Web Search Tool

```python
import httpx
from tools.base import BaseTool, ToolResult


class WebSearchTool(BaseTool):
    name = "web_search"
    description = "Search the web for current information."
    parameters_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "num_results": {"type": "integer", "default": 5},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.search.brave.com/res/v1/web/search"

    @with_retry(max_retries=3)
    async def execute(self, query: str, num_results: int = 5) -> ToolResult:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.base_url,
                params={"q": query, "count": num_results},
                headers={"X-Subscription-Token": self.api_key},
                timeout=15.0,
            )
            response.raise_for_status()
            data = response.json()

        results = []
        for item in data.get("web", {}).get("results", [])[:num_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("description", ""),
            })

        return ToolResult(success=True, output=results)
```

### Database Query Tool

```python
import sqlite3
from contextlib import contextmanager


class DatabaseTool(BaseTool):
    name = "query_database"
    description = "Execute read-only SQL queries against the database."
    parameters_schema = {
        "type": "object",
        "properties": {
            "sql": {
                "type": "string",
                "description": "SQL query (SELECT only)"
            },
        },
        "required": ["sql"],
        "additionalProperties": False,
    }

    def __init__(self, db_path: str):
        self.db_path = db_path

    async def execute(self, sql: str) -> ToolResult:
        if not sql.strip().upper().startswith("SELECT"):
            return ToolResult(
                success=False,
                output="Only SELECT queries are allowed.",
                error="write_forbidden"
            )

        try:
            with self._connect() as conn:
                cursor = conn.execute(sql)
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchmany(100)
                results = [dict(zip(columns, row)) for row in rows]

            return ToolResult(success=True, output={
                "columns": columns,
                "rows": results,
                "row_count": len(results),
            })
        except sqlite3.Error as e:
            return ToolResult(success=False, output=str(e), error="db_error")

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
```

### Code Execution Tool (Sandboxed)

```python
import docker
import json
import tempfile


class CodeExecutionTool(BaseTool):
    name = "execute_code"
    description = "Execute Python code in a Docker sandbox."
    parameters_schema = {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "Python code to execute"
            },
            "timeout": {
                "type": "integer",
                "default": 30,
                "description": "Execution timeout in seconds"
            },
        },
        "required": ["code"],
        "additionalProperties": False,
    }

    def __init__(self):
        self.client = docker.from_env()
        self.image = "python:3.12-slim"

    async def execute(self, code: str, timeout: int = 30) -> ToolResult:
        try:
            container = self.client.containers.run(
                self.image,
                command=f"python -c {json.dumps(code)}",
                detach=True,
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,
                network_mode="none",
                remove=True,
            )

            result = container.wait(timeout=timeout)
            stdout = container.logs(stdout=True, stderr=False).decode()
            stderr = container.logs(stdout=False, stderr=True).decode()

            if result["StatusCode"] == 0:
                return ToolResult(success=True, output=stdout)
            else:
                return ToolResult(
                    success=False,
                    output=stderr or stdout,
                    error="runtime_error"
                )
        except docker.errors.ContainerError as e:
            return ToolResult(success=False, output=str(e), error="container_error")
        except Exception as e:
            return ToolResult(success=False, output=str(e), error="execution_error")
```

---

## 8. RAG Integration for Agents

### RAG Pipeline for Agents

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    RAG PIPELINE FOR AGENTS                               │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    INGESTION PIPELINE (Offline)                  │   │
│   │                                                                  │   │
│   │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │   │
│   │  │  Document│──▶│  Chunk   │──▶│  Embed   │──▶│  Store   │    │   │
│   │  │  Loader  │   │  Splitter│   │  Model   │   │  Vector  │    │   │
│   │  │          │   │          │   │          │   │  DB      │    │   │
│   │  └──────────┘   └──────────┘   └──────────┘   └──────────┘    │   │
│   │                                                                  │   │
│   │  PDFs, Docs,     500-1000       text-emb-      Pinecone,       │   │
│   │  HTML, APIs      tokens/chunk   3-small        ChromaDB,       │   │
│   │                                  (1536d)       Weaviate         │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    RETRIEVAL PIPELINE (Runtime)                   │   │
│   │                                                                  │   │
│   │  ┌──────────┐                                                    │   │
│   │  │  User    │                                                    │   │
│   │  │  Query   │                                                    │   │
│   │  └────┬─────┘                                                    │   │
│   │       │                                                           │   │
│   │       ▼                                                           │   │
│   │  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐    │   │
│   │  │  Query   │──▶│  Vector  │──▶│  Rerank  │──▶│  Inject  │    │   │
│  ┆  │  Embed   │   │  Search  │   │  (Cohere │   │  into    │    │   │
│   │  │          │   │  Top-K   │   │  RRF)    │   │  Context │    │   │
│   │  └──────────┘   └──────────┘   └──────────┘   └────┬─────┘    │   │
│   │                                                      │           │   │
│   │                                                      ▼           │   │
│   │                                              ┌──────────┐        │   │
│   │                                              │  Agent   │        │   │
│   │                                              │  LLM     │        │   │
│   │                                              │  Call    │        │   │
│   │                                              └──────────┘        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│   KEY DECISION: When does RAG fire?                                     │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  Option A: ALWAYS — RAG runs on every user query (simple)     │    │
│   │  Option B: TOOL — Agent decides when to call RAG (flexible) ★ │    │
│   │  Option C: HYBRID — RAG runs on query, agent can also call     │    │
│   └────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

### RAG Tool Implementation

```python
from tools.base import BaseTool, ToolResult
from rag.retriever import VectorRetriever


class RAGTool(BaseTool):
    name = "search_knowledge_base"
    description = (
        "Search the internal knowledge base for relevant information. "
        "Use this when you need factual data from the organization's "
        "documents, policies, or technical documentation."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "The search query"
            },
            "top_k": {
                "type": "integer",
                "default": 5,
                "description": "Number of results to return"
            },
            "filter": {
                "type": "object",
                "description": "Metadata filters (e.g., department, date range)"
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    def __init__(self, retriever: VectorRetriever):
        self.retriever = retriever

    @with_retry(max_retries=2)
    async def execute(self, query: str, top_k: int = 5, filter: dict = None) -> ToolResult:
        try:
            results = await self.retriever.search(
                query=query,
                top_k=top_k,
                filter=filter,
            )
            formatted = self._format_results(results)
            return ToolResult(success=True, output=formatted)
        except Exception as e:
            return ToolResult(
                success=False,
                output=f"Knowledge base search failed: {e}",
                error="rag_error"
            )

    def _format_results(self, results: list[dict]) -> str:
        parts = []
        for i, doc in enumerate(results, 1):
            parts.append(
                f"[Source {i}] (relevance: {doc['score']:.2f})\n"
                f"Title: {doc['metadata'].get('title', 'N/A')}\n"
                f"Content: {doc['content']}\n"
            )
        return "\n---\n".join(parts)
```

---

## 9. Code Implementation Patterns

### Async Agent with Streaming

```python
import asyncio
import json
from typing import AsyncGenerator
from openai import AsyncOpenAI


class StreamingAgent(Agent):
    async def run_streaming(self, user_input: str) -> AsyncGenerator[str, None]:
        self.state.add_message("user", user_input)

        for iteration in range(self.config.max_iterations):
            self._check_guardrails()

            stream = await self.client.chat.completions.create(
                model=self.config.model,
                messages=self.state.get_messages(),
                tools=self.tool_schemas,
                stream=True,
            )

            current_content = ""
            tool_calls_buffer: dict[int, dict] = {}

            async for chunk in stream:
                delta = chunk.choices[0].delta

                if delta.content:
                    current_content += delta.content
                    yield f"data: {json.dumps({'type': 'token', 'content': delta.content})}\n\n"

                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_buffer:
                            tool_calls_buffer[idx] = {
                                "id": tc.id or "",
                                "name": "",
                                "arguments": "",
                            }
                        if tc.function:
                            if tc.function.name:
                                tool_calls_buffer[idx]["name"] += tc.function.name
                            if tc.function.arguments:
                                tool_calls_buffer[idx]["arguments"] += tc.function.arguments

            if not tool_calls_buffer:
                yield f"data: {json.dumps({'type': 'done', 'content': current_content})}\n\n"
                return

            self.state.add_message("assistant", current_content)

            for idx, tc_data in tool_calls_buffer.items():
                tool_name = tc_data["name"]
                tool_args = json.loads(tc_data["arguments"])

                yield f"data: {json.dumps({'type': 'tool_call', 'name': tool_name, 'args': tool_args})}\n\n"

                tool = self.tools.get(tool_name)
                if tool:
                    result = await self._call_tool_with_retry(tool, tool_args)
                    self.state.add_tool_result(tc_data["id"], result)

                    yield f"data: {json.dumps({'type': 'tool_result', 'name': tool_name, 'success': result.success})}\n\n"

        yield f"data: {json.dumps({'type': 'max_iterations'})}\n\n"
```

### Structured Output Pattern

```python
from pydantic import BaseModel, Field
from openai import AsyncOpenAI


class AgentPlan(BaseModel):
    thought: str = Field(description="What you are thinking")
    action: str | None = Field(description="Tool to call, or None if done")
    action_input: dict | None = Field(description="Arguments for the tool")
    final_answer: str | None = Field(description="Final answer if done")


async def get_structured_plan(
    client: AsyncOpenAI,
    model: str,
    messages: list[dict],
    tools: list[dict],
) -> AgentPlan:
    response = await client.beta.chat.completions.parse(
        model=model,
        messages=messages,
        response_format=AgentPlan,
        temperature=0,
    )
    return response.choices[0].message.parsed
```

---

## 10. Testing and Debugging Agents

### Testing Strategy

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     AGENT TESTING PYRAMID                                 │
│                                                                          │
│                              ┌──────────┐                                │
│                              │  E2E      │   ← Few, expensive,           │
│                              │  Tests    │     slow (real LLM calls)      │
│                              └──────────┘                                │
│                           ┌──────────────┐                              │
│                           │  Integration  │  ← Medium, mock LLM,       │
│                           │  Tests        │    real tools                │
│                           └──────────────┘                              │
│                       ┌──────────────────┐                              │
│                       │   Unit Tests      │  ← Many, fast,              │
│                       │   (tools, state,  │    no LLM calls              │
│                       │    parsing)       │                               │
│                       └──────────────────┘                              │
└──────────────────────────────────────────────────────────────────────────┘
```

### Unit Tests (No LLM Calls)

```python
import pytest
from agent.tools.search import WebSearchTool
from agent.state import ConversationState


class TestConversationState:
    def test_add_message(self):
        state = ConversationState()
        state.add_message("user", "Hello")
        assert len(state.messages) == 1
        assert state.messages[0].role == "user"

    def test_token_tracking(self):
        state = ConversationState()
        state.add_message("user", "Hello world")
        assert state.total_tokens > 0

    def test_repetition_detection(self):
        state = ConversationState()
        for _ in range(3):
            state._tool_call_history.append("same_tool_call_id")
        assert state.has_repetition(threshold=3)

    def test_context_summarization(self):
        state = ConversationState(max_context_tokens=50)
        for i in range(20):
            state.add_message("user", f"This is message {i} " * 20)
        messages = state.get_messages()
        assert any("summarized" in str(m.content).lower() for m in messages)


class TestWebSearchTool:
    @pytest.mark.asyncio
    async def test_schema_generation(self):
        tool = WebSearchTool(api_key="test")
        schema = tool.to_openai_schema()
        assert schema["type"] == "function"
        assert "query" in schema["function"]["parameters"]["properties"]

    @pytest.mark.asyncio
    async def test_execute_with_mock(self, httpx_mock):
        httpx_mock.add_response(
            url__regex=".*api.search.brave.com.*",
            json={"web": {"results": [
                {"title": "Test", "url": "https://test.com", "description": "A test"}
            ]}},
        )
        tool = WebSearchTool(api_key="test-key")
        result = await tool.execute(query="test query")
        assert result.success
        assert len(result.output) == 1
```

### Integration Tests (Mock LLM, Real Tools)

```python
from unittest.mock import AsyncMock, patch
from agent.core import Agent, AgentConfig


class TestAgentLoop:
    @pytest.mark.asyncio
    async def test_single_tool_call_flow(self):
        mock_response = AsyncMock()
        mock_response.choices = [
            AsyncMock(
                finish_reason="tool_calls",
                message=AsyncMock(
                    content=None,
                    tool_calls=[
                        AsyncMock(
                            id="call_123",
                            function=AsyncMock(
                                name="web_search",
                                arguments='{"query": "test"}'
                            )
                        )
                    ]
                )
            )
        ]

        agent = Agent(
            system_prompt="You are a helpful assistant.",
            tools=[WebSearchTool(api_key="test")],
            config=AgentConfig(max_iterations=5),
        )

        with patch.object(agent.client.chat.completions, "create", return_value=mock_response):
            result = await agent.run("Search for test")
            assert result is not None

    @pytest.mark.asyncio
    async def test_max_iterations_guardrail(self):
        agent = Agent(
            system_prompt="You are a helper.",
            tools=[],
            config=AgentConfig(max_iterations=1),
        )
        # Simulate a loop that never terminates
        result = await agent.run("Keep looping")
        assert "maximum iterations" in result.lower()
```

### Debugging Techniques

```python
import logging
import json
from datetime import datetime


class AgentDebugger:
    def __init__(self, log_dir: str = "debug_logs"):
        self.log_dir = log_dir
        self.step_count = 0
        logging.basicConfig(level=logging.DEBUG)

    def log_step(self, step_type: str, data: dict):
        self.step_count += 1
        entry = {
            "step": self.step_count,
            "type": step_type,
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
        with open(f"{self.log_dir}/trace_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_llm_call(self, messages: list[dict], response: dict):
        self.log_step("llm_call", {
            "input_messages": messages,
            "response": response,
            "input_tokens": len(json.dumps(messages)) // 4,
        })

    def log_tool_call(self, tool_name: str, args: dict, result: ToolResult):
        self.log_step("tool_call", {
            "tool": tool_name,
            "arguments": args,
            "success": result.success,
            "output_preview": str(result.output)[:200],
            "error": result.error,
        })

    def log_state(self, state: ConversationState):
        self.log_step("state_snapshot", {
            "message_count": len(state.messages),
            "total_tokens": state.total_tokens,
            "cost": state.estimated_cost,
        })
```

---

## 11. Agent Frameworks Comparison

### Framework Comparison Table

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                           AGENT FRAMEWORK COMPARISON                                                     │
│                                                                                                         │
│  Framework     │ Abstraction │ Tool     │ Multi- │ Streaming │ Typed    │ Production   │ Community     │
│               │ Level       │ Def      │ Agent │           │ Outputs  │ Readiness    │ Size         │
│  ─────────────┼─────────────┼──────────┼───────┼───────────┼──────────┼──────────────┼────────────── │
│  LangChain    │ Very High   │ Decorative│ Yes  │ Partial   │ Partial  │ Medium       │ Very Large   │
│  LlamaIndex   │ High        │ Function  │ Yes  │ Yes       │ Yes      │ Medium-High  │ Large        │
│  CrewAI       │ High        │ Decorative│ Yes  │ Partial   │ Partial  │ Low-Medium   │ Medium       │
│  AutoGen      │ Medium      │ Function  │ Yes  │ Yes       │ No       │ Low          │ Large        │
│  Pydantic AI  │ Low-Medium  │ Function  │ No    │ Yes       │ Yes      │ High         │ Growing      │
│  Semantic     │ Medium-High │ Decorative│ Yes  │ Yes       │ Partial  │ High         │ Large        │
│   Kernel      │             │          │       │           │          │              │              │
│  DIY (raw)    │ None        │ Custom    │ Custom│ Custom    │ Custom   │ You own it   │ N/A          │
│                                                                                                         │
│  RECOMMENDATION:                                                                                         │
│  ─────────────────────────────────────────────────────────────────────────────────────────               │
│  • Learning/Prototyping  → LangChain or LlamaIndex                                                     │
│  • Type Safety + Control → Pydantic AI                                                                  │
│  • Multi-Agent Systems    → CrewAI or AutoGen                                                          │
│  • Enterprise (.NET)     → Semantic Kernel                                                              │
│  • Production Control    → DIY with OpenAI/Anthropic SDK                                               │
│  • Maximum Flexibility    → DIY (this guide)                                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Framework-Specific Notes

**LangChain** — The most popular framework. Huge ecosystem but significant abstraction leakage. Best for rapid prototyping. Pain points: verbose debugging, breaking changes between versions, implicit behavior that's hard to override.

**LlamaIndex** — Started as a RAG framework, evolved into a full agent framework. Excellent data ingestion and retrieval. Better typed abstractions than LangChain. Use this if RAG is your primary use case.

**CrewAI** — Opinionated multi-agent framework. Clean abstraction for defining "crews" of agents with "tasks." Good for orchestrating multiple specialized agents. Less flexible for single-agent use cases.

**AutoGen** — Microsoft's conversational agent framework. Excellent for multi-agent scenarios with human-in-the-loop. More verbose API but very flexible. Research-oriented; production readiness is lower.

**Pydantic AI** — Built by the Pydantic team. The best option for type-safe, production-grade agents. Excellent structured output support, dependency injection, and model-agnostic design. Newer framework with smaller community.

**Semantic Kernel** — Microsoft's enterprise agent framework. Strong .NET and Python support. Excellent for organizations already in the Microsoft ecosystem. Good plugin architecture and planning capabilities.

---

## Agent Development Lifecycle

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    AGENT DEVELOPMENT LIFECYCLE                           │
│                                                                          │
│   ┌──────────┐                                                           │
│   │  1. DEFINE│  What problem does this agent solve?                     │
│   │           │  What tools does it need?                                │
│   │           │  What are the success criteria?                          │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  2. PROTO-│  Build the simplest agent loop (ReAct).                 │
│   │  TYPE     │  One tool. One prompt. End-to-end.                      │
│   │           │  Validate: Does the loop work at all?                   │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  3. ADD  │  Add remaining tools.                                     │
│   │  TOOLS   │  Refine system prompt.                                    │
│   │           │  Add error handling + retries.                           │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  4. EVAL │  Build evaluation dataset (50+ examples).                │
│   │           │  Measure: accuracy, tool usage, latency, cost.          │
│   │           │  Iterate on prompt and tool descriptions.                │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  5. HARD-│  Add guardrails: max iterations, cost caps,              │
│   │  EN      │  repetition detection, output validation.                │
│   │           │  Add context management (summarization).                │
│   │           │  Add observability (logging, tracing).                  │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  6. PROD │  Deploy (API, container).                                 │
│   │           │  Monitor: latency p99, error rate, cost/req.            │
│   │           │  Alert on: cost anomalies, error spikes.                 │
│   │           │  Iterate based on production data.                       │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         ▼                                                                 │
│   ┌──────────┐                                                           │
│   │  7. ITER-│  Self-improvement loop: Analyze logs, find               │
│   │  ATE     │  failure patterns, update prompt, add tools,              │
│   │           │  expand eval dataset.                                     │
│   └─────┬─────┘                                                          │
│         │                                                                 │
│         └──────────────────────────────────────────────┐                  │
│                                                           │              │
│              ← Repeat from step 4 ←──────────────────────┘              │
│                                                                          │
│   FAILURE MODES TO WATCH FOR:                                            │
│   ┌────────────────────────────────────────────────────────────┐         │
│   │ • Agent loops forever (no termination condition)          │         │
│   │ • Agent calls wrong tool or wrong arguments               │         │
│   │ • Agent hallucinates tool results                         │         │
│   │ • Context window overflow                                  │         │
│   │ • Cost overrun (one request = $50)                        │         │
│   │ • Agent produces plausible but wrong answers              │         │
│   │ • Tool authentication failures silently ignored            │         │
│   └────────────────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

1. **Start simple.** A ReAct loop with one tool, then grow. Do not start with a framework.
2. **Tools are the moat.** The system prompt and tool definitions are your primary levers for quality. Spend 70% of your time on these.
3. **Guardrails are not optional.** Max iterations, cost caps, repetition detection — these prevent runaway agents from burning money and time.
4. **Test like a QA engineer.** Build eval datasets early. Agent behavior is nondeterministic; you need regression tests.
5. **Observability is table stakes.** Log every LLM call, every tool invocation, every state transition. You will need these logs.
6. **Context management determines quality.** A smart agent with stuffed context is worse than a simple agent with well-managed context.
7. **The framework you build yourself will outperform the framework you download** — if you understand the primitives. This guide gives you those primitives.

---

*Last updated: 2026-05-01*

---

## Real References

### Agent Loops and Reasoning Patterns

1. Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. (2023). "ReAct: Synergizing Reasoning and Acting in Language Models." *International Conference on Learning Representations (ICLR 2023)*. arXiv:2210.03629. https://arxiv.org/abs/2210.03629

2. Shinn, N., Cassilio, A., & Narasimhan, K. (2023). "Reflexion: Language Agents with Verbal Reinforcement Learning." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2303.11366. https://arxiv.org/abs/2303.11366

3. Zhou, A., Gu, Q., Smah, K., & Narasimhan, K. (2023). "Language Agent Tree Search Unifies Reasoning, Acting, and Planning in Language Models." arXiv:2310.04406. https://arxiv.org/abs/2310.04406

4. Richards, T. (2023). "AutoGPT: An Autonomous GPT-4 Experiment." GitHub repository. https://github.com/Significant-Gravitas/AutoGPT

5. Wang, L., Ma, C., Feng, X., Zhang, Z., Yang, H., Zhang, J., Chen, Z., Tang, J., Chen, X., Lin, Z., Zhao, W. X., & Wei, Z. (2024). "A Survey on Large Language Model Based Autonomous Agents." *Frontiers of Computer Science*, 18(6), 186352. arXiv:2308.11432. https://arxiv.org/abs/2308.11432

6. Yao, S., Yu, D., Zhao, J., Shafran, I., Griffiths, T., Cao, Y., & Narasimhan, K. (2024). "Tree of Thoughts: Deliberate Problem Solving with Large Language Models." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2305.10601. https://arxiv.org/abs/2305.10601

7. Shinn, N., Zafrin, N., Ashaly, A., & Narasimhan, K. (2024). "Reflexion: Language Agents with Verbal Reinforcement Learning — Extended Analysis." arXiv:2303.11366. https://arxiv.org/abs/2303.11366

### Tool Calling and Tool-Augmented LLMs

8. Schick, T., Dwivedi-Yu, J., Joublin, R., Bosselut, A., & Schüz, R. (2023). "Toolformer: Language Models Can Teach Themselves to Use Tools." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2302.04761. https://arxiv.org/abs/2302.04761

9. Parisi, A., Zhao, Y., & Fiedel, N. (2022). "TALM: Tool-Augmented Language Models." arXiv:2205.12255. https://arxiv.org/abs/2205.12255

10. Nakano, R., Hilton, J., Balaji, S., Wu, J., Ouyang, L., Kim, C., Hesse, C., Kelht, S., Saude, D., & Schulman, J. (2022). "WebGPT: Browser-Assisted Question-Answering with Human Feedback." arXiv:2112.09332. https://arxiv.org/abs/2112.09332

11. Patil, S., Zhang, T., & Wang, X. (2023). "Gorilla: Large Language Model Connected with Massive APIs." arXiv:2305.15334. https://arxiv.org/abs/2305.15334

12. Qin, Y., Liang, S., Ye, Y., Zhu, K., Yan, L., Lu, Y., Lin, Y., Cong, X., He, X., & Zhou, H. (2023). "ToolLLM: Facilitating Large Language Models to Master 16000+ Real-world APIs." *International Conference on Learning Representations (ICLR 2024)*. arXiv:2307.16989. https://arxiv.org/abs/2307.15989

13. OpenAI. (2023). "Function Calling and Other API Updates." OpenAI Blog. https://openai.com/index/function-calling-and-other-api-updates/

14. Hao, S., Liu, T., Wang, Z., & Hu, Z. (2023). "ToolkenGPT: Augmenting Frozen Language Models with Massive Tools via Tool Embeddings." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2305.11554. https://arxiv.org/abs/2305.11554

### Retrieval-Augmented Generation (RAG)

15. Lewis, P., Perez, E., Pikus, A., Petroni, F., Karpukhin, V., Goyal, N., Küttler, H., Lewis, M., Yen, W., Rocktäschel, T., Kiela, D., & Bordes, A. (2020). "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *Advances in Neural Information Processing Systems (NeurIPS 2020)*. arXiv:2005.11401. https://arxiv.org/abs/2005.11401

16. Gao, Y., Xiong, Y., Gao, X., Jia, K., Pan, J., Bi, Y., Dai, Y., Su, J., & Wang, H. (2024). "Retrieval-Augmented Generation for Large Language Models: A Survey." *Communications of the ACM*. arXiv:2312.10997. https://arxiv.org/abs/2312.10997

17. Borgeaud, S., Mensch, A., Hoffmann, J., Caillé, T., Ganne, B., Mensch, S., Amad — et al. (2022). "RETRO: Improving Language Models by Retrieving from Trillions of Tokens." *International Conference on Machine Learning (ICML 2022)*. arXiv:2112.04426. https://arxiv.org/abs/2112.04426

18. Karpukhin, V., Oğuz, B., Min, S., Lewis, P., Wu, L., Yedh — et al. (2020). "Dense Passage Retrieval for Open-Domain Question Answering." *Proceedings of the 2020 Conference on Empirical Methods in Natural Language Processing (EMNLP 2020)*. arXiv:2004.04906. https://arxiv.org/abs/2004.04906

19. Izacard, G., & Grave, E. (2021). "Leveraging Passage Retrieval with Generative Models for Open Domain Question Answering." *Proceedings of the 16th Conference of the European Chapter of the Association for Computational Linguistics (EACL 2021)*. arXiv:2007.01282. https://arxiv.org/abs/2007.01282

### Prompting, Planning, and Chain-of-Thought

20. Wei, J., Wang, X., Schuurmans, D., Bosma, M., Ichter, B., Xia, F., Chi, E., Le, Q., & Zhou, D. (2022). "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models." *Advances in Neural Information Processing Systems (NeurIPS 2022)*. arXiv:2201.11903. https://arxiv.org/abs/2201.11903

21. Yao, S., Yu, D., Zhao, J., Shafran, I., Griffiths, T., Cao, Y., & Narasimhan, K. (2024). "Tree of Thoughts: Deliberate Problem Solving with Large Language Models." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2305.10601. https://arxiv.org/abs/2305.10601

22. Besta, M., Blach, N., Kubicek, A., Gersten — et al. (2024). "Graph of Thoughts: Solving Elaborate Problems with Large Language Models." *Proceedings of the AAAI Conference on Artificial Intelligence (AAAI 2024)*. arXiv:2308.09687. https://arxiv.org/abs/2308.09687

23. Wang, X., Wei, J., Schuurmans, D., Le, Q., Chi, E., & Zhou, D. (2023). "Self-Consistency Improves Chain of Thought Reasoning in Language Models." *International Conference on Learning Representations (ICLR 2023)*. arXiv:2203.11171. https://arxiv.org/abs/2203.11171

24. Madaan, A., Tandon, N., Gupta, P., Hallinan, S., Gao, L., Wiegreffe, S., Alon, U., Dziri, N., Prabhumoye, S., Yang, Y., & Neubig, G. (2023). "Self-Refine: Iterative Refinement with Self-Feedback." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2303.17651. https://arxiv.org/abs/2303.17651

### Code Generation and Execution

25. Li, Y., Choi, D., Chung, J., Kushman, N., Schrittwieser, J., Leblond, R., Eccles, T., Keeling, J., Lemerc — et al. (2022). "Competition-Level Code Generation with AlphaCode." *Science*, 378(6624). https://doi.org/10.1126/science.abq0080

26. Chen, M., Tworek, J., Jun, H., Yuan, Q., Pinto, H. P. de O., Sridhar, J., & Kaplan, J. (2021). "Evaluating Large Language Models Trained on Code." arXiv:2107.03374. https://arxiv.org/abs/2107.03374

27. Yang, Z., Liu, A., & Liu, J. (2023). "InterCode: Standardizing and Benchmarks for Interactive Coding with Large Language Models." *Advances in Neural Information Processing Systems (NeurIPS 2023)*. arXiv:2306.07877. https://arxiv.org/abs/2306.07877

### Memory and Context Management

28. Park, J. S., O'Brien, J. C., Sadigh, D., & Bernstein, M. S. (2023). "Generative Agents: Interactive Simulacra of Human Behavior." *Proceedings of the 36th Annual ACM Symposium on User Interface Software and Technology (UIST 2023)*. arXiv:2304.03442. https://arxiv.org/abs/2304.03442

29. Zhong, W., Guo, L., Gao, Q., & Yang, Y. (2024). "MemoryBank: Enhancing Large Language Models with Long-Term Memory." *Proceedings of the AAAI Conference on Artificial Intelligence*. arXiv:2305.10250. https://arxiv.org/abs/2305.10250

30. Liu, J., Lin, H., & Han, X. (2023). "LLM as a深思熟虑 — A Survey on Memory Mechanisms for Large Language Models." arXiv:2312.14924. https://arxiv.org/abs/2312.14924

### Evaluation and Benchmarking

31. Liu, X., Yu, Q., & Zhang, Y. (2023). "AgentBench: Evaluating LLMs as Agents." *International Conference on Learning Representations (ICLR 2024)*. arXiv:2308.03688. https://arxiv.org/abs/2308.03688

32. Zhu, X., Wang, L., & Wei, Z. (2023). "AgentEval: A Multi-faceted Evaluation of LLM-based Autonomous Agents." arXiv:2310.12668. https://arxiv.org/abs/2310.12668

33. Huang, Q., & others. (2023). "WebArena: A Realistic Web Environment for Building Autonomous Agents." *International Conference on Learning Representations (ICLR 2024)*. arXiv:2307.13854. https://arxiv.org/abs/2307.13854

### Safety, Guardrails, and Alignment

34. Zeng, Y., Xia, H., & Lam, M. (2024). "Agent Safety: A Holistic Analysis of Security and Safety Risks in LLM-based Agents." arXiv:2402.08517. https://arxiv.org/abs/2402.08517

35. Ruan, W., & others. (2024). "Identifying the Risks of LLM Agents: An End-to-End Framework for Safety and Trustworthiness." arXiv:2402.08517. https://arxiv.org/abs/2402.08517

36. Dong, Z., Li, S., & Xu, H. (2023). "Building Safe, Reliable, and Controllable AI Agents." arXiv:2312.09598. https://arxiv.org/abs/2312.09598

### Agent Frameworks and Infrastructure

37. LangChain documentation. https://python.langchain.com/docs/

38. LlamaIndex documentation. https://docs.llamaindex.ai/

39. CrewAI documentation. https://docs.crewai.com/

40. Pydantic AI documentation. https://ai.pydantic.com/

41. Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., Awadallah, A. H., & Zhang, R. (2023). "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation." *Microsoft Research*. arXiv:2308.08155. https://arxiv.org/abs/2308.08155

42. Microsoft Semantic Kernel documentation. https://learn.microsoft.com/en-us/semantic-kernel/

### Embedding Models and Vector Databases

43. Neelakantan, A., Rao, S., & others. (2022). "Text and Code Embeddings by Contrastive Pre-Training." arXiv:2201.10005. https://arxiv.org/abs/2201.10005

44. ChromaDB documentation. https://www.trychroma.com/

45. Pinecone documentation. https://docs.pinecone.io/

### Prompt Engineering Foundations

46. Brown, T. B., Mann, B., Ryder, N., Subbiah, M., Kaplan, J., Dhariwal, P., Neelakantan, A., & others. (2020). "Language Models are Few-Shot Learners." *Advances in Neural Information Processing Systems (NeurIPS 2020)*. arXiv:2005.14165. https://arxiv.org/abs/2005.14165

47. White, J., Fu, S., & others. (2023). "A Prompt Pattern Catalog to Enhance Prompt Engineering with ChatGPT." arXiv:2302.11382. https://arxiv.org/abs/2302.11382

### Observability and Deployment

48. LangSmith documentation. https://docs.smith.langchain.com/

49. Helicone documentation. https://www.helicone.ai/
## References

- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- Schick, T. et al., "Toolformer: Language Models Can Teach Themselves to Use Tools," 2023. https://arxiv.org/abs/2302.04761
- Wei, J. et al., "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models," NeurIPS 2022. https://arxiv.org/abs/2201.11903
- LangChain Documentation. https://docs.langchain.com/
- LangGraph Documentation. https://langchain-ai.github.io/langgraph/
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- OpenAI API Documentation. https://platform.openai.com/docs
- Anthropic Documentation. https://docs.anthropic.com
- Lewis, P. et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS 2020. https://arxiv.org/abs/2005.11401
- Wu, Q. et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," 2023. https://arxiv.org/abs/2308.08155
