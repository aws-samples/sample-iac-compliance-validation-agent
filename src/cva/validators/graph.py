"""Reference graph over normalized resources.

Resolves inter-resource references — CloudFormation ``!Ref``/``!GetAtt`` (short and
JSON forms), Terraform ``${aws_type.name.attr}``, and name-based links — into edges
so the engine can evaluate cross-resource ("graph") rules such as "no PHI database is
reachable from 0.0.0.0/0 via its security group".
"""

from __future__ import annotations

import re
from typing import Any

from cva.models import NormalizedResource

_TF_REF = re.compile(r"\$\{?\s*aws_[a-z0-9_]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_.]+\s*\}?")

# Properties that commonly hold a human-readable name other resources reference by value.
_NAME_PROPERTIES = ("BucketName", "TableName", "QueueName", "TopicName", "DomainName", "RoleName")


def _extract_ref_ids(value: Any) -> list[str]:
    """Return referenced logical IDs / names found in a property value (any nesting)."""
    ids: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            # CloudFormation short-form intrinsic, preserved by the parser.
            if "Fn::Tag" in v and "Value" in v:
                tag, val = v["Fn::Tag"], v["Value"]
                if tag == "!Ref" and isinstance(val, str):
                    ids.append(val)
                elif tag == "!GetAtt" and isinstance(val, str):
                    ids.append(val.split(".")[0])
                return
            # CloudFormation JSON form.
            if "Ref" in v and isinstance(v["Ref"], str):
                ids.append(v["Ref"])
                return
            if "Fn::GetAtt" in v:
                ga = v["Fn::GetAtt"]
                if isinstance(ga, list) and ga:
                    ids.append(str(ga[0]))
                elif isinstance(ga, str):
                    ids.append(ga.split(".")[0])
                return
            for sub in v.values():
                walk(sub)
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, str):
            m = _TF_REF.search(v)
            if m:
                ids.append(m.group(1))
            else:
                # Bare string — may be a logical id or a referenced name; keep for lookup.
                ids.append(v)

    walk(value)
    return ids


class ReferenceGraph:
    """Indexes resources and resolves references between them."""

    def __init__(self, resources: list[NormalizedResource]):
        self.resources = resources
        self._by_id: dict[str, NormalizedResource] = {r.logical_id: r for r in resources}
        self._by_name: dict[str, NormalizedResource] = {}
        for r in resources:
            for prop in _NAME_PROPERTIES:
                name = r.properties.get(prop)
                if isinstance(name, str):
                    self._by_name.setdefault(name, r)

    def follow(self, source: NormalizedResource, via: str, to_type: str | None = None) -> list[NormalizedResource]:
        """Resolve references held in ``source.properties[via]`` to target resources.

        ``via`` supports dot-notation into nested properties. Targets are filtered by
        ``to_type`` (canonical CloudFormation type) when provided.
        """
        raw = self._get_nested(source.properties, via)
        if raw is None:
            return []

        targets: list[NormalizedResource] = []
        seen: set[str] = set()
        for ref in _extract_ref_ids(raw):
            target = self._by_id.get(ref) or self._by_name.get(ref)
            if target is None or target.logical_id in seen:
                continue
            if to_type and target.resource_type != to_type:
                continue
            seen.add(target.logical_id)
            targets.append(target)
        return targets

    @staticmethod
    def _get_nested(properties: dict[str, Any], path: str) -> Any:
        current: Any = properties
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
            if current is None:
                return None
        return current
