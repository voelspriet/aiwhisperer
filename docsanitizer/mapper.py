"""
Mapping between original values and placeholders.

Handles:
- Generating consistent placeholders (same value → same placeholder)
- Normalizing values for grouping (name variations → same PERSON_XXX)
- Serializing/deserializing mapping to JSON
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Union
from pathlib import Path


@dataclass
class MappingEntry:
    """A single mapping from placeholder to original value(s)."""
    placeholder: str
    canonical: str  # The "main" form of this value
    variations: Set[str] = field(default_factory=set)  # All forms seen
    occurrences: int = 0


class Mapping:
    """
    Bidirectional mapping between original values and placeholders.

    Handles normalization so that variations of the same value
    (e.g., "El Mansouri Brahim" vs "EL MANSOURI Brahim")
    map to the same placeholder.
    """

    def __init__(self):
        self.entries: Dict[str, MappingEntry] = {}  # placeholder → entry
        self._value_to_placeholder: Dict[str, str] = {}  # normalized_value → placeholder
        self._counters: Dict[str, int] = {}  # category → count
        self.created = datetime.now().isoformat()
        self.version = "1.0"

    def get_or_create_placeholder(self, value: str, category: str) -> str:
        """
        Get existing placeholder for value, or create new one.

        Values are normalized before lookup, so variations map to same placeholder.
        """
        normalized = self._normalize(value, category)

        # Check if we already have this value
        if normalized in self._value_to_placeholder:
            placeholder = self._value_to_placeholder[normalized]
            entry = self.entries[placeholder]
            entry.variations.add(value)
            entry.occurrences += 1
            return placeholder

        # Create new placeholder
        self._counters[category] = self._counters.get(category, 0) + 1
        placeholder = f"{category}_{self._counters[category]:03d}"

        entry = MappingEntry(
            placeholder=placeholder,
            canonical=value,
            variations={value},
            occurrences=1
        )
        self.entries[placeholder] = entry
        self._value_to_placeholder[normalized] = placeholder

        return placeholder

    def get_original(self, placeholder: str) -> Optional[str]:
        """Get original (canonical) value for a placeholder."""
        entry = self.entries.get(placeholder)
        return entry.canonical if entry else None

    def _normalize(self, value: str, category: str) -> str:
        """
        Normalize a value for consistent grouping.

        For names: Handle variations like "El Mansouri" vs "EL MANSOURI"
        For phones: Remove formatting differences
        For others: Simple uppercase + strip
        """
        if category == 'PERSON':
            return self._normalize_name(value)
        elif category == 'PHONE':
            return self._normalize_phone(value)
        elif category == 'IBAN':
            return self._normalize_iban(value)
        else:
            return value.upper().strip()

    def _normalize_name(self, name: str) -> str:
        """
        Normalize person names for grouping.

        "El Mansouri Brahim" → "BRAHIM|MANSOURI"
        "EL MANSOURI Brahim" → "BRAHIM|MANSOURI"
        "ELMANSOURI Brahim"  → "BRAHIM|MANSOURI" (if we handle this case)
        """
        # Uppercase
        name = name.upper()

        # Split into parts
        parts = name.split()

        # Remove common particles
        particles = {'EL', 'AL', 'VAN', 'DE', 'DER', 'DEN', 'TEN', 'TER', 'LA', 'LE'}
        core_parts = [p for p in parts if p not in particles]

        # Sort for order-independence
        core_parts.sort()

        return '|'.join(core_parts)

    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number by removing all formatting."""
        # Remove all non-digits except leading +
        digits = re.sub(r'[^\d+]', '', phone)

        # Normalize country codes
        if digits.startswith('00'):
            digits = '+' + digits[2:]
        elif digits.startswith('0') and len(digits) == 10:
            # Belgian local number → add +32
            digits = '+32' + digits[1:]

        return digits

    def _normalize_iban(self, iban: str) -> str:
        """Normalize IBAN by removing spaces."""
        return re.sub(r'\s', '', iban.upper())

    def to_dict(self) -> dict:
        """Convert mapping to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "created": self.created,
            "statistics": {
                cat: count for cat, count in self._counters.items()
            },
            "mappings": {
                placeholder: {
                    "canonical": entry.canonical,
                    "variations": list(entry.variations),
                    "occurrences": entry.occurrences
                }
                for placeholder, entry in self.entries.items()
            }
        }

    def save(self, path: Union[str, Path]) -> None:
        """Save mapping to JSON file."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Union[str, Path]) -> 'Mapping':
        """Load mapping from JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        mapping = cls()
        mapping.version = data.get("version", "1.0")
        mapping.created = data.get("created", "")

        for placeholder, entry_data in data.get("mappings", {}).items():
            entry = MappingEntry(
                placeholder=placeholder,
                canonical=entry_data["canonical"],
                variations=set(entry_data.get("variations", [entry_data["canonical"]])),
                occurrences=entry_data.get("occurrences", 1)
            )
            mapping.entries[placeholder] = entry

            # Rebuild reverse lookup
            category = placeholder.rsplit('_', 1)[0]
            normalized = mapping._normalize(entry.canonical, category)
            mapping._value_to_placeholder[normalized] = placeholder

            # Update counter
            num = int(placeholder.rsplit('_', 1)[1])
            mapping._counters[category] = max(
                mapping._counters.get(category, 0), num
            )

        return mapping

    def __repr__(self) -> str:
        total = sum(self._counters.values())
        return f"Mapping({total} entries: {dict(self._counters)})"
