# 15 — Supervisor & Hierarchical Multi-Agent Architectures

## 15.1 Introduction

As agent systems grow beyond a handful of collaborators, unconstrained peer-to-peer communication produces chaos: duplicate work, circular delegations, and runaway token costs. Supervisor and hierarchical patterns impose **structured control flow** on top of the raw communicative capability of LLM agents. Rather than every agent talking to every other, a designated authority routes, delegates, and approves — trading flexibility for predictability, observability, and scalability.

This chapter covers the full design space: single-supervisor topologies, deep hierarchies, planner-executor splits, routing strategies, and the engineering details that make them production-viable.

---

## 15.2 The Supervisor / Orchestrator Pattern

### 15.2.1 Core Concept

A **supervisor agent** sits at the centre of a star topology. It receives the user's goal, decides which worker agent(s) to invoke, gathers their outputs, and either returns a final answer or dispatches additional work. Workers never communicate directly; all information flows through the supervisor.

```
                        ┌──────────────────────────────────────┐
                        │           SUPERVISOR AGENT           │
                        │                                      │
                        │  ┌────────────────────────────────┐  │
                        │  │        Internal State          │  │
                        │  │  ┌──────────┐  ┌───────────┐  │  │
                        │  │  │  Plan &   │  │  History   │  │  │
                        │  │  │  Scratch  │  │  Ledger    │  │  │
                        │  │  └──────────┘  └───────────┘  │  │
                        │  └────────────────────────────────┘  │
                        │                                      │
                        │  ┌────────────────────────────────┐  │
                        │  │        Routing Engine           │  │
                        │  │  ┌──────┐ ┌──────┐ ┌──────┐  │  │
                        │  │  │ LLM  │ │ Rule │ │ Tool │  │  │
                        │  │  │Select│ │Based │ │Based │  │  │
                        │  │  └──────┘ └──────┘ └──────┘  │  │
                        │  └────────────────────────────────┘  │
                        │                                      │
                        └──────┬──────┬──────┬──────┬──────────┘
                               │      │      │      │
                    ┌──────────┘      │      │      └──────────┐
                    │                 │      │                 │
                    ▼                 ▼      ▼                 ▼
              ┌───────────┐   ┌───────────┐ ┌───────────┐ ┌───────────┐
              │  Research  │   │   Code    │ │   Test    │ │  Deploy   │
              │   Agent    │   │   Agent   │ │   Agent   │ │   Agent   │
              │            │   │           │ │           │ │           │
              │ tools:     │   │ tools:    │ │ tools:    │ │ tools:    │
              │ - search   │   │ - sandbox │ │ - pytest  │ │ - kubectl │
              │ - scrape   │   │ - linter  │ │ - coverage│ │ - helm    │
              └───────────┘   └───────────┘ └───────────┘ └───────────┘
```

### 15.2.2 Single Supervisor Architecture

The simplest instantiation: one LLM-powered supervisor, *N* specialist workers.

**Key properties:**
- **Bottleneck**: The supervisor is serial — it processes one routing decision at a time.
- **Context window pressure**: The supervisor must retain the full conversation history plus each worker's output.
- **Deterministic sequencing**: The supervisor issues steps one-by-one (or in named parallel batches).

```python
class SupervisorAgent:
    def __init__(self, llm: BaseChatModel, workers: dict[str, Agent]):
        self.llm = llm
        self.workers = workers  # name → agent
        self.history: list[BaseMessage] = []
        self.scratch: str = ""

    def _build_system_prompt(self) -> str:
        worker_descriptions = "\n".join(
            f"  - {name}: {agent.description}" for name, agent in self.workers.items()
        )
        return (
            "You are a supervisor. Route the task to the most appropriate worker.\n"
            "Output a JSON object: {\"next\": <worker_name>, \"reason\": <why>}\n"
            "When done, output: {\"next\": \"FINISH\", \"response\": <final_answer>}\n\n"
            f"Available workers:\n{worker_descriptions}"
        )

    async def run(self, task: str, max_steps: int = 10) -> str:
        self.history.append(HumanMessage(content=task))
        for step in range(max_steps):
            response = await self.llm.ainvoke(
                [SystemMessage(content=self._build_system_prompt())] + self.history
            )
            decision = json.loads(response.content)
            if decision["next"] == "FINISH":
                return decision["response"]
            worker = self.workers[decision["next"]]
            result = await worker.ainvoke({"input": task, "scratch": self.scratch})
            self.history.append(AIMessage(content=f"[{decision['next']}] → {result}"))
            self.scratch += f"\n---\n{decision['next']} output:\n{result}"
        return self.scratch
```

### 15.2.3 How the Supervisor Decides Which Agent to Call

Routing is the supervisor's most critical function. Three families of strategies exist:

#### A. LLM-Based Routing
The supervisor LLM itself interprets the request and emits a structured routing decision. This is the most flexible but least predictable approach.

```python
ROUTING_PROMPT = """Given the current state:
{state}

And the available agents:
{agent_descriptions}

Decide which agent should act next, or whether the task is complete.
Respond with JSON: {{"next": "agent_name" | "FINISH", "reason": "..."}}
"""

async def llm_route(self, state: dict) -> str:
    prompt = ROUTING_PROMPT.format(
        state=json.dumps(state, indent=2),
        agent_descriptions=self._describe_agents(),
    )
    response = await self.llm.ainvoke([HumanMessage(content=prompt)])
    return json.loads(response.content)["next"]
```

**Pros:** Handles novel queries; no hardcoding.
**Cons:** Non-deterministic; costs tokens every step; can hallucinate agent names.

#### B. Rule-Based (Intent Classification) Routing
A lightweight classifier (regex, small model, or function dispatch) maps user intent to agent names before the supervisor LLM sees the message.

```python
INTENT_MAP = {
    r"(?i)(search|find|look up|research)": "research",
    r"(?i)(write|implement|code|develop)": "coder",
    r"(?i)(test|verify|check|validate)": "tester",
    r"(?i)(deploy|ship|release|rollout)": "deployer",
}

def classify_intent(message: str) -> str:
    for pattern, agent_name in INTENT_MAP.items():
        if re.search(pattern, message):
            return agent_name
    return "research"  # default fallback
```

**Pros:** Zero LLM overhead for routing; deterministic.
**Cons:** Brittle; cannot handle multi-intent messages without additional logic.

#### C. Tool-Based Routing
Each worker agent is exposed as an LLM **tool/function**. The supervisor uses standard tool-calling to dispatch. This is how LangGraph's `create_react_agent` + supervisor pattern works.

```python
from langchain_core.tools import tool

@tool
async def call_researcher(query: str) -> str:
    """Invoke the research agent for information gathering."""
    return await research_agent.ainvoke({"input": query})

@tool
async def call_coder(spec: str) -> str:
    """Invoke the coding agent to write or modify code."""
    return await coder_agent.ainvoke({"input": spec})

supervisor = create_react_agent(llm, tools=[call_researcher, call_coder])
```

**Pros:** Leverages native function-calling; clean semantics; the supervisor's own reasoning selects the tool.
**Cons:** Tool descriptions consume context; schema must stay in sync with agent capabilities.

### 15.2.4 Supervisor with Shared Memory

Starry-topology bottleneck → add a **shared memory store** that workers can read/write directly, reducing the traffic that must pass through the supervisor.

```
              ┌─────────────────────────┐
              │       Supervisor        │
              │  (routing + Oversight)  │
              └─────────┬───────────────┘
                        │  commands
          ┌─────────────┼─────────────┐
          │             │             │
    ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │ Researcher │ │   Coder   │ │   Tester  │
    └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
          │             │             │
          ▼             ▼             ▼
    ┌─────────────────────────────────────────┐
    │          SHARED MEMORY STORE             │
    │  ┌─────────┐ ┌────────┐ ┌────────────┐  │
    │  │ Scratch  │ │ Files  │ │ Facts/DB   │  │
    │  │  Pad     │ │  Map   │ │  Store     │  │
    │  └─────────┘ └────────┘ └────────────┘  │
    └─────────────────────────────────────────┘
```

```python
from langgraph.store.memory import InMemoryStore

store = InMemoryStore()

class SharedMemoryWorker:
    def __init__(self, agent: Agent, namespace: str):
        self.agent = agent
        self.namespace = namespace

    async def run(self, task: str) -> str:
        # Read shared context
        shared = store.search(self.namespace)
        context = "\n".join(item.value for item in shared)
        result = await self.agent.ainvoke(
            {"input": f"Shared context:\n{context}\n\nTask: {task}"}
        )
        # Write result back
        store.put(self.namespace, f"output_{uuid4()}", result)
        return result
```

**Trade-offs:**
- Workers can observe each other's progress without a supervisor round-trip.
- The supervisor must still coordinate *who writes when* to avoid conflicts.
- An external consistency layer (locks, CRDTs, append-only logs) may be needed for concurrent writes.

### 15.2.5 Communication Flow in the Supervisor Pattern

```
    User                                                          User
      │                                                             │
      ▼                                                             ▼
 ┌─────────┐   1. task      ┌───────────┐   2. delegate   ┌──────────┐
 │  User    │ ──────────────▶│ Supervisor│ ──────────────▶│ Worker A │
 │ Request  │                │           │                  │(Research) │
 └─────────┘                │           │ ◀────────────── │          │
                             │           │   3. result     └──────────┘
                             │           │
                             │           │   4. delegate   ┌──────────┐
                             │           │ ──────────────▶ │ Worker B │
                             │           │                  │ (Coder)  │
                             │           │ ◀────────────── │          │
                             │           │   5. result     └──────────┘
                             │           │
                             │  6. final │
                             │  answer   │
                             └─────┬─────┘
                                   │
                                   ▼
                              ┌─────────┐
                              │  User   │
                              └─────────┘

  Step 1: User sends task to supervisor
  Step 2: Supervisor analyses → delegates to Research agent
  Step 3: Research agent returns findings
  Step 4: Supervisor delegates to Coder using research output
  Step 5: Coder returns implementation
  Step 6: Supervisor synthesises → returns final answer
```

---

## 15.3 Hierarchical Pattern

### 15.3.1 Multi-Level Hierarchies

When a single supervisor's context window or decision complexity becomes overwhelming, introduce **multiple levels of management**: a director delegates to managers, each manager directs a team of workers.

```
                             ┌─────────────────────────────────────────────────┐
                             │                    DIRECTOR                      │
                             │                                                  │
                             │  Role: Strategic planning, goal decomposition    │
                             │  Scope: Full problem; cross-team coordination    │
                             │  Context: High-level; no implementation details  │
                             │                                                  │
                             │  State: ┌─────────────────────────────────┐      │
                             │         │ Master Plan                        │      │
                             │         │ ┌───────┐ ┌───────┐ ┌────────┐ │      │
                             │         │ │Phase 1│ │Phase 2│ │ Phase 3 │ │      │
                             │         │ └───────┘ └───────┘ └────────┘ │      │
                             │         └─────────────────────────────────┘      │
                             └───────┬────────────┬─────────────┬───────────────┘
                                     │            │             │
                    ┌────────────────┘            │             └────────────────┐
                    │                             │                              │
                    ▼                             ▼                              ▼
          ┌─────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
          │   RESEARCH MGR  │      │   ENGINEERING MGR   │      │   QUALITY MGR       │
          │                 │      │                     │      │                     │
          │  Role: Plan     │      │  Role: Plan &       │      │  Role: Plan &       │
          │  research       │      │  implement features │      │  validate & audit   │
          │  campaigns      │      │                     │      │                     │
          │  Scope: Info    │      │  Scope: Codebase    │      │  Scope: All         │
          │  gathering      │      │  & build system     │      │  deliverables       │
          │                 │      │                     │      │                     │
          └──┬──────┬───────┘      └──┬──────────┬──────┘      └──┬──────────┬──────┘
             │      │                 │          │                │          │
             ▼      ▼                 ▼          ▼                ▼          ▼
         ┌──────┐ ┌──────┐      ┌───────┐  ┌───────┐      ┌───────┐  ┌───────┐
         │ Web  │ │ Data │      │Front  │  │Back   │      │  Unit │ │  Sec  │
         │Search│ │Base  │      │End    │  │End    │      │ Test  │ │ Audit │
         │Agent │ │Agent │      │Agent  │  │Agent  │      │ Agent │ │ Agent │
         └──────┘ └──────┘      └───────┘  └───────┘      └───────┘ └───────┘


    LEVEL 0 (Director):   "Build an e-commerce platform with payment integration"
    LEVEL 1 (Managers):   Director decomposes into:
                            - Research Mgr:  "Survey payment providers & regulations"
                            - Eng Mgr:      "Implement cart, checkout, payment flow"
                            - Quality Mgr:  "Define test strategy, security audit"
    LEVEL 2 (Workers):    Each manager decomposes further:
                            - Web Search Agent: "Search Stripe, PayPal APIs"
                            - Frontend Agent:  "Build React checkout component"
                            - Backend Agent:   "Implement payment API endpoints"
                            - Unit Test Agent: "Write pytest suite for checkout"
                            - Security Agent:  "OWASP audit on payment endpoints"
```

### 15.3.2 Delegation and Escalation

Hierarchical systems need **clear protocols** for downward delegation and upward escalation:

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class EscalationReason(Enum):
    BLOCKED = "blocked"               # Cannot proceed; needs input from another team
    SCOPE_EXCEEDED = "scope_exceeded" # Task requires resources/authority beyond this level
    AMBIGUITY = "ambiguity"           # Requirement is unclear
    FAILURE = "failure"               # Worker failed after max retries
    CONFLICT = "conflict"             # Outputs from two workers contradict each other

@dataclass
class Delegation:
    task: str
    target: str                         # worker or sub-manager name
    context: dict = field(default_factory=dict)
    constraints: list[str] = field(default_factory=list)
    deadline_steps: int = 5             # max steps before mandatory escalation

@dataclass
class Escalation:
    reason: EscalationReason
    original_task: str
    partial_result: Optional[str] = None
    details: str = ""

class HierarchicalAgent:
    def __init__(self, name: str, role: str, llm: BaseChatModel,
                 subordinates: dict[str, "HierarchicalAgent"] | None = None,
                 parent: Optional["HierarchicalAgent"] = None):
        self.name = name
        self.role = role
        self.llm = llm
        self.subordinates = subordinates or {}
        self.parent = parent
        self.state: dict = {}

    async def delegate(self, delegation: Delegation) -> str:
        worker = self.subordinates[delegation.target]
        self.state[f"delegated_{delegation.target}"] = delegation.task
        try:
            result = await worker.execute(delegation.task, delegation.context)
            return result
        except Exception as e:
            if self.parent:
                escalation = Escalation(
                    reason=EscalationReason.FAILURE,
                    original_task=delegation.task,
                    details=str(e),
                )
                return await self.escalate(escalation)
            raise

    async def escalate(self, escalation: Escalation) -> str:
        # Pass the problem up to the parent for resolution
        return await self.parent.handle_escalation(escalation)

    async def handle_escalation(self, escalation: Escalation) -> str:
        # Director/manager decides: re-delegate, modify constraints, or ask user
        decision_prompt = (
            f"Escalation received: {escalation.reason.value}\n"
            f"Original task: {escalation.original_task}\n"
            f"Details: {escalation.details}\n"
            f"Subordinates available: {list(self.subordinates.keys())}\n"
            f"Decide: re-delegate to different worker, modify task, or ask user."
        )
        response = await self.llm.ainvoke([HumanMessage(content=decision_prompt)])
        return response.content
```

### 15.3.3 Hierarchical Planning and Decomposition

The director level performs **work breakdown structure (WBS)** creation. This mirrors how human organisations decompose projects:

```
    ┌─────────────────────────────────────────────────────────────────────┐
    │                        DIRECTOR'S PLANNING PHASE                    │
    │                                                                     │
    │  Input: "Build a data pipeline that ingests CSVs, validates them,   │
    │          transforms them, and loads into a data warehouse"          │
    │                                                                     │
    │  Step 1: DECOMPOSE into phases                                      │
    │  ┌──────────────────────────────────────────────────────────────┐   │
    │  │ Plan:                                                          │   │
    │  │   Phase 1 → Research existing tools & schemas                 │   │
    │  │   Phase 2 → Implement ingestion (Director → Eng Mgr)         │   │
    │  │   Phase 3 → Implement validation (Director → Eng Mgr)        │   │
    │  │   Phase 4 → Implement transformation (Director → Eng Mgr)    │   │
    │  │   Phase 5 → Implement loading (Director → Eng Mgr)           │   │
    │  │   Phase 6 → Test end-to-end (Director → Quality Mgr)         │   │
    │  │   Phase 7 → Deploy (Director → DevOps Mgr)                   │   │
    │  └──────────────────────────────────────────────────────────────┘   │
    │                                                                     │
    │  Step 2: IDENTIFY dependencies                                      │
    │  ┌──────────────────────────────────────────────────────────────┐   │
    │  │ Dependency graph:                                              │   │
    │  │   Phase 2 depends on Phase 1 ──┐                              │   │
    │  │   Phase 3 depends on Phase 2 ───┤                              │   │
    │  │   Phase 4 depends on Phase 2 ───┼── can run in parallel       │   │
    │  │   Phase 5 depends on Phase 3 ───┤                              │   │
    │  │   Phase 6 depends on Phase 5 ───┘                              │   │
    │  │   Phase 7 depends on Phase 6                                   │   │
    │  └──────────────────────────────────────────────────────────────┘   │
    │                                                                     │
    │  Step 3: DELEGATE each phase to appropriate manager                 │
    └─────────────────────────────────────────────────────────────────────┘
```

```python
@dataclass
class PlanStep:
    id: str
    task: str
    assignee: str              # manager or worker name
    dependencies: list[str] = field(default_factory=list)
    status: str = "pending"    # pending | in_progress | done | blocked | failed

class DirectorAgent:
    def __init__(self, llm: BaseChatModel, managers: dict[str, HierarchicalAgent]):
        self.llm = llm
        self.managers = managers
        self.plan: list[PlanStep] = []

    async def create_plan(self, goal: str) -> list[PlanStep]:
        prompt = (
            "You are a director. Decompose the following goal into ordered steps.\n"
            "For each step, specify: id, task, assignee (one of: "
            f"{list(self.managers.keys())}), and dependencies (list of step ids).\n"
            f"Goal: {goal}\n\nRespond in JSON."
        )
        response = await self.llm.ainvoke([HumanMessage(content=prompt)])
        steps = json.loads(response.content)
        self.plan = [PlanStep(**s) for s in steps]
        return self.plan

    async def execute_plan(self) -> dict[str, str]:
        results = {}
        while any(s.status != "done" for s in self.plan):
            ready = [
                s for s in self.plan
                if s.status == "pending"
                and all(self._dep_status(d) == "done" for d in s.dependencies)
            ]
            for step in ready:
                step.status = "in_progress"
                manager = self.managers[step.assignee]
                result = await manager.execute(step.task)
                results[step.id] = result
                step.status = "done" if result else "failed"
            if not ready:
                break  # deadlock or all done
        return results

    def _dep_status(self, dep_id: str) -> str:
        for s in self.plan:
            if s.id == dep_id:
                return s.status
        return "pending"
```

### 15.3.4 State Management in Hierarchical Systems

State at each level differs in granularity and scope. Mismatches cause the classic "telephone game" problem:

```
    ┌────────────────────────────────────────────────────────────────────┐
    │                      STATE MANAGEMENT LAYERS                       │
    │                                                                    │
    │  LEVEL 0 — Director State                                         │
    │  ┌──────────────────────────────────────────────────────────────┐  │
    │  │  • Master plan (phases, dependencies, status)                 │  │
    │  │  • Cross-team coordination facts                              │  │
    │  │  • User-facing conversation history                            │  │
    │  │  • High-level risk register                                    │  │
    │  └──────────────────────────────────────────────────────────────┘  │
    │       │ condensation          │ expansion                         │
    │       ▼ (summarise)           ▼ (elaborate)                       │
    │  LEVEL 1 — Manager State                                         │
    │  ┌──────────────────────────────────────────────────────────────┐  │
    │  │  • Sub-plan for their team (tasks, assignments)               │  │
    │  │  • Relevant facts from director (filtered)                    │  │
    │  │  • Worker output summaries (condensed from full outputs)      │  │
    │  │  • Team-specific scratch pad                                  │  │
    │  └──────────────────────────────────────────────────────────────┘  │
    │       │ condensation          │ expansion                         │
    │       ▼ (summarise)           ▼ (elaborate)                       │
    │  LEVEL 2 — Worker State                                          │
    │  ┌──────────────────────────────────────────────────────────────┐  │
    │  │  • Specific task instructions plus context                    │  │
    │  │  • Full tool state: files read, APIs called, data retrieved   │  │
    │  │  • Uncompressed work product (code, reports, test logs)       │  │
    │  │  • Execution trace for debugging                             │  │
    │  └──────────────────────────────────────────────────────────────┘  │
    │                                                                    │
    │  KEY PRINCIPLE: Information flows DOWN expanded, flows UP          │
    │  condensed. Each level keeps only what it needs.                   │
    └────────────────────────────────────────────────────────────────────┘
```

```python
class HierarchicalState:
    """Maintains state at each level with appropriate granularity."""

    def __init__(self, level: int, name: str):
        self.level = level
        self.name = name
        self.local_state: dict = {}
        self.upward_buffer: list[str] = []   # summaries for parent
        self.downward_buffer: list[str] = []  # elaborated context for children

    def condense_for_parent(self, full_output: str) -> str:
        """Compress worker output into a summary suitable for the parent's
        context window. At lower levels, keep more detail; at higher levels,
        only keep actionable conclusions."""
        prompt = (
            f"You are summarising output for a manager. "
            f"Condense the following into 3-5 bullet points "
            f"focusing on: decisions made, results achieved, blockers encountered.\n\n"
            f"{full_output}"
        )
        response = self.llm.invoke([HumanMessage(content=prompt)])
        self.upward_buffer.append(response.content)
        return response.content

    def expand_for_child(self, parent_context: str, task: str) -> str:
        """Take the condensed parent context and add back the details
        a child worker needs to execute effectively."""
        prompt = (
            f"A manager has assigned you this task: {task}\n\n"
            f"Here is context from above: {parent_context}\n\n"
            f"Expand this context with specific implementation details "
            f"needed to execute the task. Include relevant constraints, "
            f"style guides, and success criteria."
        )
        response = self.llm.invoke([HumanMessage(content=prompt)])
        self.downward_buffer.append(response.content)
        return response.content
```

---

## 15.4 Supervisor with Planner Agents

### 15.4.1 Separating Planning from Execution

A common pitfall in supervisor systems: the supervisor both *plans* and *executes*, cycling between "what should I do next?" and "do it." Separating these concerns yields cleaner architectures:

```
    ┌─────────────────────────────────────────────────────────────────────┐
    │                   SUPERVISOR WITH PLANNER PATTERN                   │
    │                                                                     │
    │  ┌──────────────────┐                         ┌────────────────┐  │
    │  │    PLANNER AGENT  │                         │  USER REQUEST  │  │
    │  │                    │                         └───────┬────────┘  │
    │  │  Input: Goal       │                                │           │
    │  │  Output: Plan      │◀───────────────────────────────┘           │
    │  │                    │                                                   │
    │  │  ┌──────────────┐ │                                                    │
    │  │  │ Plan State:  │ │         ┌──────────────────────────────────┐    │
    │  │  │              │ │         │      VALIDATION / REVISION       │    │
    │  │  │ Step 1: ... │ │───────▶ │                                  │    │
    │  │  │ Step 2: ... │ │  draft  │  ┌────────────┐ ┌────────────┐  │    │
    │  │  │ Step 3: ... │ │  plan   │  │ Feasibility│ │ Dependency │  │    │
    │  │  │ Step 4: ... │ │         │  │   Check    │ │   Check    │  │    │
    │  │  └──────────────┘ │         │  └────────────┘ └────────────┘  │    │
    │  └────────┬─────────┘         │         │                       │    │
    │           │                    │    pass │     fail │            │    │
    │           │ approved plan     │         ▼         ▼            │    │
    │           │                    │  ┌─────────────────────────┐   │    │
    │           ▼                    │  │  Revised Plan / Reject   │   │    │
    │  ┌──────────────────┐         │  └──────────┬──────────────┘   │    │
    │  │   SUPERVISOR       │         └─────────────┼─────────────────┘    │
    │  │   (Executor)      │◀──────────────────────┘                      │
    │  │                    │  approved plan                               │
    │  │  ┌──────────────┐ │                                               │
    │  │  │ Execution:   │ │                                               │
    │  │  │              │ │       ┌─────────────┐                         │
    │  │  │ Step 1 → A   │───────▶│  Worker A    │                         │
    │  │  │ Step 2 → B   │───────▶│  Worker B    │                         │
    │  │  │ Step 3 → C   │───────▶│  Worker C    │                         │
    │  │  └──────────────┘ │       └─────────────┘                         │
    │  └──────────────────┘                                                │
    └─────────────────────────────────────────────────────────────────────┘
```

### 15.4.2 Plan Validation and Revision

Before execution begins, a separate validation pass catches structural problems:

```python
@dataclass
class PlanStep:
    id: str
    description: str
    assignee: str
    dependencies: list[str]
    estimated_complexity: str  # "low" | "medium" | "high"
    success_criteria: str

@dataclass
class ValidatedPlan:
    steps: list[PlanStep]
    validated: bool
    issues: list[str]
    revised_steps: list[PlanStep] | None = None

class PlanValidator:
    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    async def validate(self, plan: list[PlanStep], goal: str) -> ValidatedPlan:
        issues: list[str] = []

        # 1. Check for circular dependencies
        if self._has_circular_deps(plan):
            issues.append("Circular dependency detected in plan steps.")

        # 2. Check that all dependencies reference existing steps
        step_ids = {s.id for s in plan}
        for step in plan:
            for dep in step.dependencies:
                if dep not in step_ids:
                    issues.append(f"Step {step.id} depends on non-existent step {dep}.")

        # 3. LLM-based feasibility check
        feasibility = await self._llm_feasibility_check(plan, goal)
        issues.extend(feasibility)

        if not issues:
            return ValidatedPlan(steps=plan, validated=True, issues=[])

        # Attempt revision
        revised = await self._llm_revise_plan(plan, goal, issues)
        return ValidatedPlan(
            steps=plan, validated=False, issues=issues, revised_steps=revised
        )

    def _has_circular_deps(self, plan: list[PlanStep]) -> bool:
        adj = {s.id: s.dependencies for s in plan}
        visited, stack = set(), set()
        def visit(n):
            if n in stack: return True
            if n in visited: return False
            visited.add(n); stack.add(n)
            for dep in adj.get(n, []):
                if visit(dep): return True
            stack.discard(n); return False
        return any(visit(s.id) for s in plan)

    async def _llm_feasibility_check(self, plan, goal) -> list[str]:
        prompt = (
            f"Goal: {goal}\n\nPlan steps:\n"
            + "\n".join(f"  {s.id}: {s.description} (assignee: {s.assignee})" for s in plan)
            + "\n\nList any issues: missing steps, wrong assignee, impossible dependencies."
        )
        resp = await self.llm.ainvoke([HumanMessage(content=prompt)])
        return [line.strip("- ") for line in resp.content.split("\n") if line.strip().startswith("-")]

    async def _llm_revise_plan(self, plan, goal, issues) -> list[PlanStep]:
        prompt = (
            f"Goal: {goal}\n\nCurrent plan has these issues:\n"
            + "\n".join(f"  - {i}" for i in issues)
            + "\n\nProduce a revised plan in JSON."
        )
        resp = await self.llm.ainvoke([HumanMessage(content=prompt)])
        revised = json.loads(resp.content)
        return [PlanStep(**s) for s in revised]
```

### 15.4.3 Plan-Execute-Replan Loop

Even approved plans may fail during execution. A **replanning** mechanism adjusts the plan when step results diverge from expectations:

```python
class PlanExecuteAgent:
    def __init__(self, planner, supervisor, validator, max_replans: int = 3):
        self.planner = planner
        self.supervisor = supervisor
        self.validator = validator
        self.max_replans = max_replans

    async def run(self, goal: str) -> str:
        plan = await self.planner.create_plan(goal)
        validated = await self.validator.validate(plan, goal)
        plan = validated.revised_steps if validated.revised_steps else validated.steps

        results: dict[str, str] = {}
        replans_remaining = self.max_replans

        for step in list(plan):
            if not self._deps_met(step, results):
                continue  # skip; will be handled upon replan if needed

            result = await self.supervisor.delegate(step)
            results[step.id] = result

            # Evaluate whether we need to replan
            if not self._step_succeeded(step, result):
                if replans_remaining > 0:
                    new_plan = await self.planner.replan(
                        goal, original_plan=plan,
                        failed_step=step, result=result,
                        completed=results
                    )
                    validated = await self.validator.validate(new_plan, goal)
                    plan = validated.revised_steps or validated.steps
                    replans_remaining -= 1
                else:
                    raise RuntimeError(f"Step {step.id} failed; no replans remaining.")

        return self._synthesize(results, goal)

    def _deps_met(self, step: PlanStep, results: dict) -> bool:
        return all(d in results for d in step.dependencies)

    def _step_succeeded(self, step: PlanStep, result: str) -> bool:
        # Simple heuristic; replace with LLM-based evaluation
        return len(result) > 10 and "error" not in result.lower()

    def _synthesize(self, results: dict, goal: str) -> str:
        return "\n".join(f"Step {k}: {v}" for k, v in results.items())
```

---

## 15.5 LLM-Based Routing vs. Fixed Routing

### 15.5.1 Routing Decision Tree

```
                         ┌─────────────────────┐
                         │  TASK ARRIVES AT    │
                         │  SUPERVISOR         │
                         └──────────┬──────────┘
                                    │
                         ┌──────────▼──────────┐
                         │  Can task be         │
                         │  classified by       │
                         │  simple rules?        │
                         │  (regex, keywords,   │
                         │   intent taxonomy)   │
                         └─────┬─────────┬─────┘
                          YES  │         │  NO
                               │         │
                    ┌──────────▼──┐  ┌───▼───────────────┐
                    │  FIXED      │  │  LLM-BASED         │
                    │  ROUTING    │  │  ROUTING            │
                    │             │  │                     │
                    │  ┌────────┐ │  │  ┌───────────────┐  │
                    │  │Lookup  │ │  │  │ LLM reasons   │  │
                    │  │table / │ │  │  │ about task,   │  │
                    │  │regex / │ │  │  │ available     │  │
                    │  │intent  │ │  │  │ agents, and   │  │
                    │  │map     │ │  │  │ context       │  │
                    │  └───┬────┘ │  │  └──────┬────────┘  │
                    │      │      │  │         │            │
                    │      ▼      │  │         ▼            │
                    │  Deterministic│  │  Flexible but      │
                    │  routing     │  │  non-deterministic  │
                    │  (O(1))      │  │  (O(tokens))       │
                    └──────┬──────┘  └──────┬──────────────┘
                           │                │
                    ┌──────▼────────────────▼──────┐
                    │  HYBRID: Fixed routing for    │
                    │  high-confidence classifications│
                    │  + LLM fallback for ambiguous  │
                    │  or multi-intent tasks          │
                    └────────────────────────────────┘
```

### 15.5.2 Comparative Analysis

| Dimension | LLM-Based Routing | Fixed Routing | Hybrid |
|---|---|---|---|
| **Latency per step** | 200–800 ms (LLM call) | <1 ms (lookup) | Mixed |
| **Cost per step** | $0.001–$0.01 (tokens) | $0 (compute only) | Variable |
| **Accuracy on known intents** | 90–95% | 99%+ (if rule exists) | 99%+ |
| **Accuracy on novel intents** | 80–90% | 0% (falls to default) | 80–90% |
| **Maintainability** | Update system prompt | Update rule set | Both |
| **Observability** | Opaque reasoning | Fully transparent | Mixed |
| **Multi-intent handling** | Natural via chain-of-thought | Requires explicit FSM | Both |

### 15.5.3 Hybrid Router Implementation

```python
class HybridRouter:
    def __init__(self, rules: list[tuple[str, str]], llm: BaseChatModel,
                 agents: dict[str, Agent], default_agent: str):
        self.rules = [(re.compile(p), a) for p, a in rules]
        self.llm = llm
        self.agents = agents
        self.default_agent = default_agent
        self.confidence_threshold = 0.85

    async def route(self, message: str, state: dict) -> str:
        # Phase 1: Try fixed rules
        for pattern, agent_name in self.rules:
            if pattern.search(message):
                return agent_name

        # Phase 2: LLM-based routing with confidence
        agent_descriptions = "\n".join(
            f"  {name}: {agent.description}" for name, agent in self.agents.items()
        )
        prompt = (
            f"Given the message: '{message}'\n"
            f"Current state: {json.dumps(state)[:500]}\n\n"
            f"Available agents:\n{agent_descriptions}\n\n"
            f"Which agent should handle this? Respond with JSON:\n"
            f'{{"agent": "name", "confidence": 0.0-1.0, "reason": "..."}}'
        )
        response = await self.llm.ainvoke([HumanMessage(content=prompt)])
        decision = json.loads(response.content)

        if decision["confidence"] >= self.confidence_threshold:
            return decision["agent"]

        # Phase 3: Low confidence → ask user or use default
        return self.default_agent
```

---

## 15.6 Pattern Selection Decision Framework

### 15.6.1 Pattern Selection Flowchart

```
                          ┌─────────────────────┐
                          │  What is your        │
                          │  multi-agent problem? │
                          └──────────┬──────────┘
                                     │
                          ┌──────────▼──────────┐
                          │  How many distinct   │
                          │  agent roles?        │
                          └─────┬─────────┬─────┘
                          ≤3    │         │  ≥4
                                │         │
                    ┌───────────▼──┐  ┌───▼────────────────┐
                    │  SUPERVISOR  │  │  Is there a natural   │
                    │  + WORKERS   │  │  organizational       │
                    │  (flat)      │  │  hierarchy?           │
                    └──────────────┘  └───┬────────┬─────────┘
                                       YES │        │ NO
                                           │        │
                              ┌─────────────▼──┐ ┌───▼───────────────┐
                              │  HIERARCHICAL  │ │  SUPERVISOR        │
                              │  (2-3 levels)  │ │  + PLANNER         │
                              └────┬───────────┘ │  (separate plan    │
                                   │              │   from execution)  │
                                   │              └────────────────────┘
                          ┌────────▼─────────────┐
                          │  Does planning need   │
                          │  validation before     │
                          │  execution?            │
                          └─────┬─────────┬──────┘
                           YES  │         │  NO
                                │         │
                    ┌───────────▼────┐ ┌───▼──────────────┐
                    │  HIERARCHICAL  │ │  HIERARCHICAL     │
                    │  WITH PLANNER  │ │  (pure delegate)  │
                    │  (plan-validate│ │                    │
                    │   -execute)    │ │                    │
                    └────────────────┘ └───────────────────┘
```

### 15.6.2 Decision Heuristics

| Condition | Recommended Pattern | Rationale |
|---|---|---|
| 2–3 agents, clear role boundaries | Flat supervisor | Simple to implement; supervisor can hold all context |
| 4+ agents, same domain | Flat supervisor + shared memory | Avoids supervisor bottleneck on data passing |
| Agents span distinct domains (research, engineering, QA) | Hierarchical (2-level) | Domain managers reduce supervisor's planning burden |
| 6+ agents, multi-phase projects | Hierarchical (3-level) with planner | Director plans phases; managers plan tasks; workers execute |
| High-stakes decisions, audit trail required | Supervisor + planner + validation | Validation gate catches bad plans before costly execution |
| Streaming/real-time tasks | Flat supervisor with tool-based routing | Minimises routing latency |
| Highly dynamic agent pool (agents added/removed) | LLM-based routing | No hardcoded agent names needed |
| Cost-sensitive, high-volume | Fixed routing with regex fallback | Avoids LLM tokens on every routing decision |

### 15.6.3 When NOT to Use Hierarchical Patterns

- **Low-latency requirements**: Each management layer adds one or more LLM calls.
- **Simple pipelines**: If tasks are strictly sequential (A → B → C), use a pipeline, not a hierarchy.
- **Small team (2–3 agents)**: The overhead of manager agents outweighs the coordination benefit.
- **Stateless operations**: If agents don't share state, a simple dispatcher suffices.

---

## 15.7 Implementation Details and Code Patterns

### 15.7.1 LangGraph Supervisor Implementation

```python
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing import Annotated, Literal
from typing_extensions import TypedDict

class SupervisorState(TypedDict):
    messages: Annotated[list, add_messages]
    next: str
    scratch: str

def supervisor_node(state: SupervisorState) -> dict:
    """Routes to the next worker or finishes."""
    system = (
        "You are a supervisor. Given the conversation, decide the next worker.\n"
        f"Available: {list(WORKERS.keys())}\n"
        "Output JSON: {\"next\": \"worker_name\" | \"FINISH\"}"
    )
    response = llm.invoke(
        [SystemMessage(content=system)] + state["messages"]
    )
    decision = json.loads(response.content)
    return {"next": decision["next"]}

def worker_node(worker_name: str):
    def node(state: SupervisorState) -> dict:
        result = WORKERS[worker_name].invoke(state["messages"])
        return {
            "messages": [AIMessage(content=f"[{worker_name}]: {result}")],
            "scratch": state.get("scratch", "") + f"\n{worker_name}: {result}",
        }
    return node

def router(state: SupervisorState) -> Literal[*WORKERS.keys(), "supervisor"]:
    return state["next"]

# Build the graph
graph = StateGraph(SupervisorState)
graph.add_node("supervisor", supervisor_node)
for name in WORKERS:
    graph.add_node(name, worker_node(name))

graph.add_edge(START, "supervisor")
graph.add_conditional_edges("supervisor", router)
for name in WORKERS:
    graph.add_edge(name, "supervisor")
graph.add_edge("supervisor", END)  # when next == FINISH

app = graph.compile()
```

### 15.7.2 Hierarchical LangGraph Implementation

```python
class ManagerState(TypedDict):
    messages: Annotated[list, add_messages]
    task: str
    plan: list[dict]
    results: dict[str, str]

def director_node(state: dict) -> dict:
    """Top-level director decomposes the goal and delegates to managers."""
    goal = state["messages"][-1].content
    plan = llm.invoke([
        SystemMessage(content="Decompose this goal into manager-level tasks."),
        HumanMessage(content=goal),
    ])
    steps = json.loads(plan.content)
    return {"plan": steps, "task": goal}

def manager_node(manager_name: str, workers: dict):
    """Manager receives a sub-goal and coordinates workers."""
    def node(state: dict) -> dict:
        sub_goal = state["task"]
        worker_plan = llm.invoke([
            SystemMessage(content=f"You are the {manager_name} manager. Plan worker tasks."),
            HumanMessage(content=sub_goal),
        ])
        tasks = json.loads(worker_plan.content)
        results = {}
        for task in tasks:
            worker = workers[task["assignee"]]
            result = worker.invoke(task["description"])
            results[task["id"]] = result
        return {"results": results}
    return node

# Build hierarchical graph
hierarchy = StateGraph(ManagerState)
hierarchy.add_node("director", director_node)
hierarchy.add_node("research_mgr", manager_node("Research", RESEARCH_WORKERS))
hierarchy.add_node("eng_mgr", manager_node("Engineering", ENG_WORKERS))

hierarchy.add_edge(START, "director")
hierarchy.add_conditional_edges("director", lambda s: "research_mgr" if "research" in s["plan"].lower() else "eng_mgr")
hierarchy.add_edge("research_mgr", END)
hierarchy.add_edge("eng_mgr", END)

hierarchical_app = hierarchy.compile()
```

### 15.7.3 Checkpointing for Fault Tolerance

Supervisor systems must survive interruptions. LangGraph's persistence layer enables checkpointing:

```python
from langgraph.checkpoint.memory import MemorySaver
from langgraph.checkpoint.sqlite import SqliteSaver

# In-memory (development)
checkpointer = MemorySaver()
app = graph.compile(checkpointer=checkpointer)

# SQLite (production)
checkpointer = SqliteSaver.from_conn_string("checkpoints.db")
app = graph.compile(checkpointer=checkpointer)

# Resume after interruption
config = {"configurable": {"thread_id": "session-123"}}
result = app.invoke({"messages": [HumanMessage(content="Research quantum computing")]}, config)

# Later, resume from last checkpoint
result = app.invoke({"messages": [HumanMessage(content="Continue")]}, config)
```

### 15.7.4 Human-in-the-Loop Integration

For high-stakes decisions, inject a human approval gate:

```python
from langgraph.types import interrupt

def supervisor_with_approval(state: SupervisorState) -> dict:
    plan = create_plan(state)
    # Interrupt execution to get human approval
    human_response = interrupt(
        f"Proposed plan:\n{json.dumps(plan, indent=2)}\n\nApprove? (yes/no/modify)"
    )
    if human_response["approved"]:
        return {"next": plan[0]["assignee"], "plan": plan}
    elif human_response.get("modified_plan"):
        return {"next": human_response["modified_plan"][0]["assignee"],
                "plan": human_response["modified_plan"]}
    else:
        return {"next": "FINISH", "messages": [AIMessage(content="Plan rejected.")]}

app = graph.compile(
    checkpointer=checkpointer,
    interrupt_before=["approval_node"],
)
```

---

## 15.8 Scaling Considerations

### 15.8.1 Token Budget Management

Each management layer consumes tokens. At scale, this dominates cost:

```
    Layer          Tokens/step    Steps/Task    Total Tokens
    ─────────────────────────────────────────────────────────
    Director          500           1              500
    Manager (×3)     1000          ×3            3,000
    Workers (×9)      800          ×9            7,200
    ─────────────────────────────────────────────────────────
    TOTAL PER TASK                                10,700

    At $3/M input tokens (GPT-4-class):
      Cost per task ≈ $0.032
      1,000 tasks/day ≈ $32/day
      100,000 tasks/day ≈ $3,200/day
```

**Mitigation strategies:**
1. **Summarise aggressively**: Workers return summaries, not raw output, to their manager.
2. **Compress history**: Use sliding-window context with periodic consolidation.
3. **Cache routing decisions**: Similar queries → same worker; skip LLM routing.
4. **Use smaller models for routing**: GPT-3.5-class models suffice for classification; reserve GPT-4-class for complex reasoning.

### 15.8.2 Concurrency and Parallelism

```
    ┌─────────────────────────────────────────────────────────────────┐
    │                    PARALLEL EXECUTION                           │
    │                                                                 │
    │    Sequential (3 steps):          Parallel (3 steps):          │
    │                                                                 │
    │    ┌───┐                          ┌───┐                        │
    │    │ A │ 5s                       │ A │ 5s  ─┐                 │
    │    └─┬─┘                          └───┘      │                  │
    │      │                            ┌───┐      │ 5s total        │
    │    ┌───┐                          │ B │ 3s  ─┤ (max of all)    │
    │    │ B │ 3s                       └───┘      │                  │
    │    └─┬─┘                          ┌───┐      │                  │
    │      │                            │ C │ 4s  ─┘                 │
    │    ┌───┐                          └───┘                        │
    │    │ C │ 4s                                                     │
    │    └───┘       Total: 12s              Total: 5s                │
    │                                                                 │
    │    ─────────────────────────────────────────────────────────    │
    │    Parallelism requires the supervisor to emit FAN-OUT          │
    │    commands with independent agent calls.                       │
    └─────────────────────────────────────────────────────────────────┘
```

```python
import asyncio

class ParallelSupervisor(SupervisorAgent):
    async def run(self, task: str, max_steps: int = 10) -> str:
        self.history.append(HumanMessage(content=task))
        for step in range(max_steps):
            routing = await self._plan_step(self.history)
            if routing["next"] == "FINISH":
                return routing["response"]

            # Fan-out: dispatch multiple independent workers
            if isinstance(routing["next"], list):
                tasks = [
                    self.workers[name].ainvoke({"input": task, "scratch": self.scratch})
                    for name in routing["next"]
                ]
                results = await asyncio.gather(*tasks)
                for name, result in zip(routing["next"], results):
                    self.history.append(AIMessage(content=f"[{name}] → {result}"))
                    self.scratch += f"\n---\n{name} output:\n{result}"
            else:
                worker = self.workers[routing["next"]]
                result = await worker.ainvoke({"input": task, "scratch": self.scratch})
                self.history.append(AIMessage(content=f"[{routing['next']}] → {result}"))
                self.scratch += f"\n---\n{routing['next']} output:\n{result}"
        return self.scratch
```

### 15.8.3 Hierarchical Scaling Limits

| Hierarchy Depth | Max Concurrent Workers | Context Window Pressure | Routing Latency | Failure Blast Radius |
|---|---|---|---|---|
| 1 (flat supervisor) | ~10 | High (all workers' output) | 1 LLM call | All workers affected |
| 2 (supervisor + managers) | ~50 | Medium (summarised per team) | 2 LLM calls | Team-only |
| 3 (director + managers + leads) | ~200+ | Low (condensed per team) | 3 LLM calls | Isolated to sub-team |

**Recommendation**: Stay at depth 2 unless you have >20 workers. Depth 3+ is only justified for large organisations (50+ concurrent agents), and the complexity cost (debugging, state management, latency) grows non-linearly.

### 15.8.4 Observability in Hierarchical Systems

```python
import structlog

logger = structlog.get_logger()

class ObservableHierarchicalAgent:
    def __init__(self, name: str, level: int, **kwargs):
        self.name = name
        self.level = level
        self.logger = logger.bind(agent=name, level=level)

    async def execute(self, task: str, context: dict | None = None):
        span_id = f"{self.name}-{uuid4().hex[:8]}"
        self.logger.info("task_start", span=span_id, task=task[:200])

        try:
            result = await self._do_execute(task, context)
            self.logger.info("task_complete", span=span_id, result_len=len(result))
            return result
        except Exception as e:
            self.logger.error("task_failed", span=span_id, error=str(e))
            raise
        finally:
            self.logger.info("task_end", span=span_id)

    async def delegate(self, delegation: Delegation):
        self.logger.info(
            "delegating",
            from_agent=self.name,
            to_agent=delegation.target,
            task=delegation.task[:200],
        )
        result = await self.subordinates[delegation.target].execute(
            delegation.task, delegation.context
        )
        self.logger.info(
            "delegation_complete",
            from_agent=self.name,
            to_agent=delegation.target,
            result_len=len(result),
        )
        return result
```

---

## 15.9 Summary

| Pattern | Best For | Key Trade-off |
|---|---|---|
| **Single Supervisor** | Small teams (2–5 agents), straightforward tasks | Simple but bottlenecked; supervisor context fills up fast |
| **Supervisor + Shared Memory** | Teams that produce large intermediate artifacts | Reduces supervisor traffic; requires conflict resolution |
| **Supervisor + Tool Routing** | When workers expose clear function interfaces | Clean semantics; coupling between tools and agents |
| **Hierarchical (2-level)** | Multi-domain teams (4+ agents, distinct specialties) | Reduces supervisor load; adds manager overhead |
| **Hierarchical (3-level)** | Large-scale projects (10+ agents, phased delivery) | Excellent scaling; complex debugging and state management |
| **Supervisor + Planner** | High-stakes or irreversible tasks | Catches bad plans early; adds latency and tokens |
| **Hybrid Routing** | Production systems with common + novel queries | Deterministic for known intents; flexible for edge cases |

The choice of architecture is not permanent. Start simple — a flat supervisor with LLM-based routing — and add hierarchy, planners, or shared memory only when specific bottlenecks emerge. Premature hierarchy is as damaging as premature optimisation: each additional layer costs tokens, latency, and debugging complexity. Measure first, then restructure.

---

## Real References

1. Anthropic, "Building Effective Agents", 2024. https://www.anthropic.com/research/building-effective-agents

2. LangGraph Documentation — Supervisor Pattern and Multi-Agent Architectures. https://langchain-ai.github.io/langgraph/

3. Park, J.S., O'Brien, J.C., Shaw, C., et al., "Generative Agents: Interactive Simulacra of Human Behavior", *Proceedings of the 36th Annual ACM Symposium on User Interface Software and Technology (UIST 2023)*, 2023. arXiv:2304.03442

4. Wu, Q., Bansal, G., Zhang, J., et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation", 2023. arXiv:2308.08155

5. Hong, S., Zhuge, M., Chen, J., et al., "MetaGPT: Meta Programming for A Multi-Agent Collaborative Framework", *Proceedings of the International Conference on Learning Representations (ICLR 2024)*, 2024. arXiv:2308.00352

6. Talebirad, Y., Nadiri, A., "Multi-Agent Collaboration: Harnessing the Power of Multiple LLM Agents", 2023. arXiv:2309.00783

7. CrewAI Documentation — Multi-Agent Orchestration and Hierarchical Process. https://docs.crewai.com/

8. Liu, X., Chen, K., Cui, P., et al., "Large Language Model-based Multi-Agent Systems: A Survey of Paradigms, Architectures, and Applications", 2024. arXiv:2402.05128

9. Guo, T., Chen, X., Wang, Y., et al., "Large Language Model based Multi-Agents: A Survey of Challenges and Solutions", 2024. arXiv:2402.01680

10. Wang, L., Ma, C., Feng, X., et al., "A Survey on Large Language Model Based Autonomous Agents", *Frontiers of Computer Science*, 2024. arXiv:2308.11432

11. Du, Y., Li, S., Torralba, A., et al., "Improving Factuality and Reasoning in Language Models through Multiagent Debate", *Proceedings of the 41st International Conference on Machine Learning (ICML 2024)*, 2024. arXiv:2305.14325

12. Liang, T., Sun, Z., He, J., et al., "TaskWeaver: A Code-First Agent Framework", 2023. arXiv:2311.05373

13. Significant Gravitas, "AutoGPT — An Autonomous GPT-4 Experiment", 2023. https://github.com/Significant-Gravitas/AutoGPT

14. OpenAI, "Swarm: Educational Framework for Lightweight Multi-Agent Orchestration", 2024. https://github.com/openai/swarm

15. Microsoft Research, "Magentic-One: A Generalist Multi-Agent System for Solving Complex Tasks", 2024. arXiv:2411.04468

16. Chen, W., Su, Y., Yan, J., et al., "ChatDev: Communicative Agents for Software Development", *Proceedings of the 62nd Annual Meeting of the Association for Computational Linguistics (ACL 2024)*, 2024. arXiv:2307.07964

17. Qian, C., Zhang, Z., Yang, C., et al., "Communicative Agents for Software Development", 2023. arXiv:2307.07964

18. Deetz, R.J., "Design Patterns for Multi-Agent Systems: Reusing Proven Solutions", *Proceedings of the International Workshop on Agent-Oriented Software Engineering*, Springer, 2004. DOI:10.1007/978-3-540-32849-0_5

19. Weiss, G. (Ed.), *Multiagent Systems: A Modern Approach to Distributed Artificial Intelligence*, MIT Press, 2nd edition, 2013. ISBN:978-0262522045

20. Wooldridge, M., *An Introduction to MultiAgent Systems*, John Wiley & Sons, 2nd edition, 2009. ISBN:978-0470742164

21. Dorri, A., Kanhere, S.S., Jurdak, R., "Multi-Agent Systems: A Survey", *IEEE Access*, vol. 6, pp. 28573–28593, 2018. DOI:10.1109/ACCESS.2018.2839346

22. Lee, M., He, X., Song, D., "Orchestrating LLM-Based Multi-Agent Systems for Complex Problem Solving", 2024. arXiv:2402.18525

23. Zhang, Y., Wang, X., "Multi-Agent Systems with Large Language Models: Architectures, Challenges and Future Directions", 2024. arXiv:2402.12369

24. Xi, Z., Chen, W., Guo, D., et al., "The Rise and Potential of Large Language Model Based Agents: A Survey", 2023. arXiv:2309.07864
## References

- Wu, Q. et al., "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," 2023. https://arxiv.org/abs/2308.08155
- Park, J.S. et al., "Generative Agents: Interactive Simulacra of Human Behavior," UIST 2023. https://arxiv.org/abs/2304.03442
- LangGraph Documentation — Hierarchical Agent Patterns. https://langchain-ai.github.io/langgraph/
- CrewAI Documentation. https://docs.crewai.com/
- OpenAI, "GPT-4 Technical Report," 2023. https://arxiv.org/abs/2303.08774
- Yao, S. et al., "ReAct: Synergizing Reasoning and Acting in Language Models," ICLR 2023. https://arxiv.org/abs/2210.03629
- Nash, J., "Non-Cooperative Games," Annals of Mathematics, 1951 — foundational game theory for hierarchical coordination.
- "Managing AI Agents at Scale: Orchestration, Monitoring, and Governance," various, 2024.
- OpenAI API Documentation. https://platform.openai.com/docs
- Anthropic Documentation. https://docs.anthropic.com
