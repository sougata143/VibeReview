# tests/unit/test_observability.py
import pytest
import asyncio
from unittest.mock import MagicMock

from opentelemetry import trace, context as otel_context
from opentelemetry.trace import StatusCode, SpanContext, TraceFlags
from opentelemetry.sdk.trace import TracerProvider, Span
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app.telemetry import TailBasedSamplingProcessor, ObservabilityPlugin
from app.security import SecurityAnomalyException

class MockSpanProcessor(SimpleSpanProcessor):
    def __init__(self, exporter):
        super().__init__(exporter)

@pytest.fixture
def sampling_setup():
    exporter = InMemorySpanExporter()
    downstream = SimpleSpanProcessor(exporter)
    sampler = TailBasedSamplingProcessor(downstream, self_repair_threshold=3)
    
    # Create a test tracer
    provider = TracerProvider()
    provider.add_span_processor(sampler)
    tracer = provider.get_tracer("test-tracer")
    
    return sampler, exporter, tracer

def test_tail_sampler_drops_successful_routine_trace(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        with tracer.start_as_current_span("child1") as c1:
            c1.set_status(StatusCode.OK)
        with tracer.start_as_current_span("child2") as c2:
            c2.set_status(StatusCode.OK)
            
    # After exiting root_span, the trace is evaluated
    assert trace_id in sampler.evaluated_trace_ids
    assert trace_id not in sampler.retained_trace_ids
    # Span should not be exported
    assert len(exporter.get_finished_spans()) == 0

def test_tail_sampler_retains_error_trace(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        with tracer.start_as_current_span("child1") as c1:
            c1.set_status(StatusCode.ERROR, "Mock error")
            
    # Trace should be retained
    assert trace_id in sampler.retained_trace_ids
    assert len(exporter.get_finished_spans()) > 0

def test_tail_sampler_retains_policy_violation_by_attribute(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        root_span.set_attribute("policy_violation", True)
        
    assert trace_id in sampler.retained_trace_ids
    assert len(exporter.get_finished_spans()) > 0

def test_tail_sampler_retains_policy_violation_by_exception(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        with tracer.start_as_current_span("child") as child:
            try:
                raise SecurityAnomalyException("Security anomaly triggered")
            except Exception as e:
                child.record_exception(e)
                
    assert trace_id in sampler.retained_trace_ids
    assert len(exporter.get_finished_spans()) > 0

def test_tail_sampler_retains_excessive_self_repair_loops_sandbox(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        # 3 calls to execute_sandbox
        for i in range(3):
            with tracer.start_as_current_span("agent.tool") as tool_span:
                tool_span.set_attribute("tool.name", "execute_sandbox")
                
    assert trace_id in sampler.retained_trace_ids
    assert len(exporter.get_finished_spans()) > 0

def test_tail_sampler_retains_excessive_self_repair_loops_models(sampling_setup):
    sampler, exporter, tracer = sampling_setup
    
    with tracer.start_as_current_span("root") as root_span:
        trace_id = root_span.get_span_context().trace_id
        # 3 calls to generate_content
        for i in range(3):
            with tracer.start_as_current_span("generate_content_gemini"):
                pass
                
    assert trace_id in sampler.retained_trace_ids
    assert len(exporter.get_finished_spans()) > 0

@pytest.mark.asyncio
async def test_observability_plugin_lifecycle():
    plugin = ObservabilityPlugin()
    
    # Mock parameters for callbacks
    agent_mock = MagicMock()
    agent_mock.name = "test_agent"
    
    tool_mock = MagicMock()
    tool_mock.name = "test_tool"
    
    callback_context_mock = MagicMock()
    tool_context_mock = MagicMock()
    
    # Verify agent think callbacks start and end spans
    await plugin.before_agent_callback(agent=agent_mock, callback_context=callback_context_mock)
    assert hasattr(callback_context_mock, "otel_span")
    assert hasattr(callback_context_mock, "otel_token")
    
    # End agent callback
    await plugin.after_agent_callback(agent=agent_mock, callback_context=callback_context_mock)
    
    # Verify tool call callbacks start and end spans
    await plugin.before_tool_callback(tool=tool_mock, tool_args={"x": 1}, tool_context=tool_context_mock)
    assert hasattr(tool_context_mock, "otel_span")
    assert hasattr(tool_context_mock, "otel_token")
    
    # End tool callback
    await plugin.after_tool_callback(tool=tool_mock, tool_args={"x": 1}, tool_context=tool_context_mock, result={})
