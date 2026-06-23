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

import uuid
from typing import (
    Literal,
)

from pydantic import (
    BaseModel,
    Field,
)


class Feedback(BaseModel):
    """Represents feedback for a conversation."""

    score: int | float
    text: str | None = ""
    log_type: Literal["feedback"] = "feedback"
    service_name: Literal["vibe-review"] = "vibe-review"
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class UpdateComponentsPayload(BaseModel):
    surfaceId: str
    components: list[dict]


class A2UIPayload(BaseModel):
    version: str = "v0.9"
    updateComponents: UpdateComponentsPayload


class HybridResponse(BaseModel):
    data: dict
    ui: A2UIPayload
    ui_available: bool


from a2ui.schema.manager import A2uiSchemaManager
from a2ui.basic_catalog import BasicCatalog

schema_manager = A2uiSchemaManager(
    version="0.9",
    catalogs=[BasicCatalog.get_config("0.9")]
)

