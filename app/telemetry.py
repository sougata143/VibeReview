# app/telemetry.py
# OpenTelemetry setup for tracing the Vibe Trajectory.

import collections
import logging
from typing import Any, Optional

from opentelemetry import trace, context as otel_context
from opentelemetry.trace import StatusCode, set_span_in_context
from opentelemetry.sdk.trace import SpanProcessor, Span
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.agents.callback_context import CallbackContext
from google.adk.tools.tool_context import ToolContext
from google.genai import types

logger = logging.getLogger("vibe-review.telemetry")

class TailBasedSamplingProcessor(SpanProcessor):
    """
    OpenTelemetry SpanProcessor that implements tail-based sampling.
    It buffers spans in-memory per trace ID and evaluates the trace after completion.
    
    Traces are retained if they contain:
    - Any ERROR span status or recorded exceptions.
    - Any policy violation indicator (attributes, session quarantine/blocked state, or security exceptions).
    - Excessive self-repair loops (>= 3 tool executions or model generation calls).
    
    Routine successful traces are dropped.
    """
    def __init__(self, exporter_processor: SpanProcessor, self_repair_threshold: int = 3):
        self.exporter_processor = exporter_processor
        self.self_repair_threshold = self_repair_threshold
        # Buffer to accumulate spans per trace ID
        self.buffer = collections.defaultdict(list)
        # Tracking for test assertions
        self.retained_trace_ids = set()
        self.evaluated_trace_ids = set()

    def on_start(self, span: Span, parent_context=None) -> None:
        pass

    def on_end(self, span: Span) -> None:
        trace_id = span.context.trace_id
        self.buffer[trace_id].append(span)

        # A span is root if parent is None or has invalid SpanContext
        is_root = (span.parent is None) or (not span.parent.is_valid)

        if is_root:
            spans = self.buffer.pop(trace_id, [])
            self.evaluated_trace_ids.add(trace_id)
            if self._should_retain(spans):
                self.retained_trace_ids.add(trace_id)
                logger.info(f"[TailSampler] RETAINING trace {trace_id:032x}")
                for s in spans:
                    self.exporter_processor.on_start(s)
                    self.exporter_processor.on_end(s)
            else:
                logger.info(f"[TailSampler] DROPPING trace {trace_id:032x}")

    def _should_retain(self, spans: list[Span]) -> bool:
        # 1. Check for errors
        for span in spans:
            if span.status.status_code == StatusCode.ERROR:
                return True
            for event in span.events:
                if event.name == "exception":
                    return True

        # 2. Check for policy violations
        for span in spans:
            attrs = span.attributes or {}
            if attrs.get("policy_violation") or attrs.get("blocked_by_rbac") or attrs.get("agent_status") == "QUARANTINED":
                return True
            for event in span.events:
                if event.name == "exception":
                    exc_type = event.attributes.get("exception.type", "")
                    if any(t in exc_type for t in ["SecurityAnomalyException", "QuarantinedStateException"]):
                        return True

        # 3. Check for excessive self-repair loops (model or execute_sandbox tools >= threshold)
        sandbox_calls = 0
        model_calls = 0
        for span in spans:
            if span.name == "agent.tool" and span.attributes.get("tool.name") == "execute_sandbox":
                sandbox_calls += 1
            if "generate_content" in span.name:
                model_calls += 1

        if sandbox_calls >= self.self_repair_threshold or model_calls >= self.self_repair_threshold:
            return True

        return False


class ObservabilityPlugin(BasePlugin):
    """
    ADK plugin to trace agent execution loops (think latency) and tool calls (tool latency).
    Also checks session state at invocation completion to inject policy violation attributes.
    """
    def __init__(self):
        super().__init__(name="observability_plugin")
        self.tracer = trace.get_tracer("vibe-review-tracer")

    async def before_agent_callback(
        self, *, agent, callback_context: CallbackContext
    ) -> Optional[types.Content]:
        span = self.tracer.start_span("agent.think", context=otel_context.get_current())
        span.set_attribute("agent.name", agent.name)
        token = otel_context.attach(set_span_in_context(span))
        setattr(callback_context, "otel_span", span)
        setattr(callback_context, "otel_token", token)
        return None

    async def after_agent_callback(
        self, *, agent, callback_context: CallbackContext
    ) -> Optional[types.Content]:
        span = getattr(callback_context, "otel_span", None)
        token = getattr(callback_context, "otel_token", None)
        if token:
            otel_context.detach(token)
        if span:
            span.end()
        return None

    async def before_tool_callback(
        self,
        *,
        tool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[dict]:
        span = self.tracer.start_span("agent.tool", context=otel_context.get_current())
        span.set_attribute("tool.name", tool.name)
        span.set_attribute("tool.args", str(tool_args))
        token = otel_context.attach(set_span_in_context(span))
        setattr(tool_context, "otel_span", span)
        setattr(tool_context, "otel_token", token)
        return None

    async def after_tool_callback(
        self,
        *,
        tool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict,
    ) -> Optional[dict]:
        span = getattr(tool_context, "otel_span", None)
        token = getattr(tool_context, "otel_token", None)
        if token:
            otel_context.detach(token)
        if span:
            span.end()
        return None

    async def on_tool_error_callback(
        self,
        *,
        tool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> Optional[dict]:
        span = getattr(tool_context, "otel_span", None)
        token = getattr(tool_context, "otel_token", None)
        if token:
            otel_context.detach(token)
        if span:
            span.record_exception(error)
            span.set_status(trace.StatusCode.ERROR, str(error))
            span.end()
        return None

    async def after_run_callback(self, *, invocation_context) -> None:
        session = invocation_context.session
        state = getattr(session, "state", {}) or {}
        if (
            state.get("agent_status") == "QUARANTINED"
            or state.get("remediation_triggered")
            or state.get("blocked_by_rbac")
        ):
            current_span = trace.get_current_span()
            if current_span:
                current_span.set_attribute("policy_violation", True)
                current_span.set_attribute("agent_status", state.get("agent_status", ""))
                current_span.set_attribute("remediation_triggered", state.get("remediation_triggered", False))
                current_span.set_attribute("blocked_by_rbac", state.get("blocked_by_rbac", False))
