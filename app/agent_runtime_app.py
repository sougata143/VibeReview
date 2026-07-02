# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import os
import json
from typing import Any, Union, Dict, Optional, List, AsyncIterable

import vertexai
from dotenv import load_dotenv
from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.cloud import logging as google_cloud_logging
from vertexai.agent_engines.templates.adk import AdkApp

from app.agent import app as adk_app
from app.app_utils.telemetry import setup_telemetry
from app.app_utils.typing import Feedback, HybridResponse, A2UIPayload, UpdateComponentsPayload

# Load environment variables from .env file at runtime
load_dotenv()


def format_hybrid_response(raw_text: str) -> dict:
    """Helper to convert raw text findings to a structured HybridResponse."""
    raw_lower = raw_text.lower()
    has_user_enum = "user enumeration" in raw_lower or "user_enumeration" in raw_lower or "enumeration" in raw_lower
    has_weak_hash = "weak hashing" in raw_lower or "hash" in raw_lower
    has_jwt = "jwt" in raw_lower or "token" in raw_lower
    
    # Check for SAST / SCA / Code Smells
    has_sast = "sast" in raw_lower or "sql injection" in raw_lower or "command injection" in raw_lower or "cryptography" in raw_lower or "path traversal" in raw_lower or "xss" in raw_lower
    has_sca = "sca" in raw_lower or "vulnerable dependency" in raw_lower or "outdated dependency" in raw_lower
    has_smells = "code smell" in raw_lower or "empty except" in raw_lower or "broad exception" in raw_lower or "todo" in raw_lower
    
    vulnerabilities = []
    if has_user_enum:
        vulnerabilities.append("User Enumeration in login responses")
    if has_weak_hash:
        vulnerabilities.append("Weak SHA-256 Hashing for passwords")
    if has_jwt:
        vulnerabilities.append("7-day long JWT Token Expiration policy")
    if has_sast:
        vulnerabilities.append("SAST Vulnerabilities (Injection/Insecure Crypto) detected")
    if has_sca:
        vulnerabilities.append("SCA Vulnerable/Outdated Dependencies flagged")
    if has_smells:
        vulnerabilities.append("SonarQube Code Smells / Quality issues found")
        
    if not vulnerabilities:
        vulnerabilities.append("Low risk: No immediate vulnerabilities identified.")

    data_payload = {
        "vulnerabilities_found": bool(vulnerabilities and "Low risk" not in vulnerabilities[0]),
        "raw_output": raw_text,
        "metrics": {
            "user_enumeration": has_user_enum,
            "weak_hashing": has_weak_hash,
            "insecure_jwt": has_jwt,
            "sast_vulnerabilities": has_sast,
            "sca_vulnerabilities": has_sca,
            "code_smells": has_smells
        }
    }
    
    ui_components = [
        {
            "id": "root",
            "type": "Container",
            "children": ["title", "vulnerabilities_list"]
        },
        {
            "id": "title",
            "type": "Header",
            "properties": {
                "text": "VibeReview Security Audit Report"
            }
        },
        {
            "id": "vulnerabilities_list",
            "type": "List",
            "properties": {
                "items": vulnerabilities
            }
        }
    ]
    
    response = HybridResponse(
        data=data_payload,
        ui=A2UIPayload(
            version="v0.9",
            updateComponents=UpdateComponentsPayload(
                surfaceId="vibe-review-surface",
                components=ui_components
            )
        ),
        ui_available=True
    )
    return response.model_dump(mode="json")


class AgentEngineApp(AdkApp):
    def set_up(self) -> None:
        """Initialize the agent engine app with logging and telemetry."""
        # 1. Custom OpenTelemetry configuration for Glass Box Observability & Tail-Based Sampling
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
        from app.telemetry import TailBasedSamplingProcessor, ObservabilityPlugin

        # Create global TracerProvider
        provider = TracerProvider()
        # Use ConsoleSpanExporter as downstream exporter to capture trace details
        console_exporter = ConsoleSpanExporter()
        downstream_processor = SimpleSpanProcessor(console_exporter)
        
        # Instantiate tail-based sampling processor
        self.tail_sampler = TailBasedSamplingProcessor(downstream_processor)
        provider.add_span_processor(self.tail_sampler)

        # Set the global tracer provider safely (avoiding override exceptions in multi-run contexts)
        if "Proxy" in type(trace.get_tracer_provider()).__name__:
            trace.set_tracer_provider(provider)
            logging.info("Registered global TracerProvider with TailBasedSamplingProcessor.")
        else:
            logging.warning("TracerProvider already configured; custom tail-sampler may not receive all spans.")

        # Register ObservabilityPlugin for agent.think and agent.tool span hooks
        if not any(isinstance(p, ObservabilityPlugin) for p in adk_app.plugins):
            adk_app.plugins.append(ObservabilityPlugin())
            logging.info("ObservabilityPlugin registered successfully.")

        vertexai.init()
        setup_telemetry()
        super().set_up()
        logging.basicConfig(level=logging.INFO)
        if os.environ.get("INTEGRATION_TEST", "FALSE").upper() == "TRUE":
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"
            os.environ["GOOGLE_GENAI_USE_ENTERPRISE"] = "False"
            class MockLogger:
                def log_struct(self, info, **kwargs):
                    logging.info(f"MockLogger log_struct: {info}")
            self.logger = MockLogger()
        else:
            logging_client = google_cloud_logging.Client()
            self.logger = logging_client.logger(__name__)
        if gemini_location:
            os.environ["GOOGLE_CLOUD_LOCATION"] = gemini_location

    def register_feedback(self, feedback: dict[str, Any]) -> None:
        """Collect and log feedback."""
        feedback_obj = Feedback.model_validate(feedback)
        self.logger.log_struct(feedback_obj.model_dump(), severity="INFO")

    def register_operations(self) -> dict[str, list[str]]:
        """Registers the operations of the Agent."""
        operations = super().register_operations()
        operations[""] = [*operations.get("", []), "register_feedback"]
        return operations

    def clone(self) -> "AgentEngineApp":
        """Returns a clone of the Agent Runtime application."""
        return self

    async def async_stream_query(
        self,
        *,
        message: Union[str, Dict[str, Any]],
        user_id: str,
        session_id: Optional[str] = None,
        session_events: Optional[List[Dict[str, Any]]] = None,
        run_config: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> AsyncIterable[Dict[str, Any]]:
        from opentelemetry import trace, context as otel_context
        tracer = trace.get_tracer("vibe-review-tracer")
        
        span = tracer.start_span("agent.session")
        if session_id:
            span.set_attribute("session.id", session_id)
        if user_id:
            span.set_attribute("user.id", user_id)
            
        token = otel_context.attach(trace.set_span_in_context(span))
        
        accumulated_text = ""
        events_list = []
        
        try:
            async for event in super().async_stream_query(
                message=message,
                user_id=user_id,
                session_id=session_id,
                session_events=session_events,
                run_config=run_config,
                **kwargs
            ):
                events_list.append(event)
                content = event.get("content")
                if content and "parts" in content:
                    for part in content["parts"]:
                        if "text" in part and part["text"]:
                            accumulated_text += part["text"]
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.StatusCode.ERROR, str(e))
            raise
        finally:
            otel_context.detach(token)
            span.end()
        
        if accumulated_text:
            formatted_dict = format_hybrid_response(accumulated_text)
            formatted_json = json.dumps(formatted_dict)
            
            updated = False
            for event in reversed(events_list):
                content = event.get("content")
                if content and "parts" in content:
                    for part in content["parts"]:
                        if "text" in part:
                            part["text"] = formatted_json
                            updated = True
                            break
                    if updated:
                        break
            if not updated and events_list:
                events_list[-1]["content"] = {
                    "role": "model",
                    "parts": [{"text": formatted_json}]
                }
        
        for event in events_list:
            yield event

    def stream_query(
        self,
        *,
        message: Union[str, Dict[str, Any]],
        user_id: str,
        session_id: Optional[str] = None,
        run_config: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        from opentelemetry import trace, context as otel_context
        tracer = trace.get_tracer("vibe-review-tracer")
        
        span = tracer.start_span("agent.session")
        if session_id:
            span.set_attribute("session.id", session_id)
        if user_id:
            span.set_attribute("user.id", user_id)
            
        token = otel_context.attach(trace.set_span_in_context(span))
        
        accumulated_text = ""
        events_list = []
        
        try:
            for event in super().stream_query(
                message=message,
                user_id=user_id,
                session_id=session_id,
                run_config=run_config,
                **kwargs
            ):
                events_list.append(event)
                content = event.get("content")
                if content and "parts" in content:
                    for part in content["parts"]:
                        if "text" in part and part["text"]:
                            accumulated_text += part["text"]
        except Exception as e:
            span.record_exception(e)
            span.set_status(trace.StatusCode.ERROR, str(e))
            raise
        finally:
            otel_context.detach(token)
            span.end()
                        
        if accumulated_text:
            formatted_dict = format_hybrid_response(accumulated_text)
            formatted_json = json.dumps(formatted_dict)
            
            updated = False
            for event in reversed(events_list):
                content = event.get("content")
                if content and "parts" in content:
                    for part in content["parts"]:
                        if "text" in part:
                            part["text"] = formatted_json
                            updated = True
                            break
                    if updated:
                        break
            if not updated and events_list:
                events_list[-1]["content"] = {
                    "role": "model",
                    "parts": [{"text": formatted_json}]
                }
                
        for event in events_list:
            yield event


gemini_location = os.environ.get("GOOGLE_CLOUD_LOCATION")
logs_bucket_name = os.environ.get("LOGS_BUCKET_NAME")
agent_runtime = AgentEngineApp(
    app=adk_app,
    artifact_service_builder=lambda: (
        GcsArtifactService(bucket_name=logs_bucket_name)
        if logs_bucket_name
        else InMemoryArtifactService()
    ),
)

