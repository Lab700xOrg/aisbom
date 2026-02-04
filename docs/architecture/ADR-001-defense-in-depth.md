# ADR-001: Pivot to "Defense in Depth" (Static Analysis Limitations)

*   **Status:** Accepted
*   **Date:** Feb 3, 2026

## 1. The Context

Initially, AIsbom aimed to be a "Security Gate" that deterministically blocked malicious models using static analysis of Pickle bytecode (disassembling opcodes without execution).

## 2. The Problem (The "Inference Wall")

Feedback from security researchers (at Cisco and the Google Bouncer team) highlighted intrinsic mathematical limitations in this approach:

1.  **The Halting Problem:** Accurately predicting the behavior of a stack-based VM (Pickle) without executing it is impossible against adversarial obfuscation.
2.  **The "Gadget" Problem:** Attackers can use `builtins.getattr` to construct malicious calls dynamically (e.g., `getattr(os, 'sys'+'tem')`), bypassing static blocklists.
3.  **The "Screen Door" Effect:** Static analysis catches accidental risks (90%) but fails against determined attackers (10%).

As the creator of `beartype` noted: "Static analysis is limited because Python is magical... standard dunder methods destroy the ability to reason statically."

## 3. The Decision

We are shifting the architecture from **"Pure Prevention"** to **"Defense in Depth."**

We effectively split the product into two layers:

*   **Layer 1: Hygiene (Static):** The `aisbom` CLI remains a static analyzer. Its goal is **Speed and Migration**. It catches low-hanging fruit (scripted malware, license risks) and helps developers migrate to `weights_only=True`. It is not a sandbox.
*   **Layer 2: Isolation (Dynamic):** For high-threat models, we now officially support and recommend **Runtime Sandboxing**. We integrated wrappers for `amazing-sandbox` (`asb`) to detonate models in ephemeral containers.

## 4. Consequences

*   **Trade-off:** We no longer claim "100% protection" from malware in the CLI alone.
*   **Benefit:** We provide a realistic, enterprise-grade workflow (Filter fast -> Sandbox slow) rather than a false sense of security.
*   **Roadmap:** Future engineering focuses on **Migration Linting** (helping devs fix models) rather than an arms race against obfuscation.
