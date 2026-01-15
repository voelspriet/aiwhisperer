"""
Anonymization strategies for PII data.

Different strategies for different use cases:
- replace: Substitute with placeholders (reversible with mapping)
- redact: Remove completely with generic marker
- mask: Partial redaction preserving format
- hash: One-way transformation (SHA256)
- encrypt: Reversible encryption (Fernet)

Based on: https://mstack.nl/blogs/anonymize-pii-llm/
"""

import hashlib
import re
import secrets
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class AnonymizedValue:
    """Result of anonymization."""
    original: str
    anonymized: str
    category: str
    strategy: str
    metadata: Dict[str, Any] = None  # For encryption keys, etc.


class AnonymizationStrategy(ABC):
    """Base class for anonymization strategies."""

    name: str = "base"

    @abstractmethod
    def anonymize(self, value: str, category: str, **kwargs) -> AnonymizedValue:
        """Anonymize a value."""
        pass

    def can_deanonymize(self) -> bool:
        """Whether this strategy supports deanonymization."""
        return False


class ReplaceStrategy(AnonymizationStrategy):
    """
    Replace with placeholder tokens.

    Example: "Jan de Vries" → "PERSON_001"

    This is reversible using the mapping file.
    """

    name = "replace"

    def __init__(self):
        self._counters: Dict[str, int] = {}

    def anonymize(self, value: str, category: str, placeholder: str = None, **kwargs) -> AnonymizedValue:
        if placeholder is None:
            self._counters[category] = self._counters.get(category, 0) + 1
            placeholder = f"{category}_{self._counters[category]:03d}"

        return AnonymizedValue(
            original=value,
            anonymized=placeholder,
            category=category,
            strategy=self.name,
        )

    def can_deanonymize(self) -> bool:
        return True


class RedactStrategy(AnonymizationStrategy):
    """
    Redact completely with a generic marker.

    Example: "Jan de Vries" → "[REDACTED]"

    Options:
    - marker: Custom redaction marker (default: "[REDACTED]")
    - include_category: Include category in marker (default: True)
    """

    name = "redact"

    def __init__(self, marker: str = "[REDACTED]", include_category: bool = True):
        self.marker = marker
        self.include_category = include_category

    def anonymize(self, value: str, category: str, **kwargs) -> AnonymizedValue:
        if self.include_category:
            anonymized = f"[{category}]"
        else:
            anonymized = self.marker

        return AnonymizedValue(
            original=value,
            anonymized=anonymized,
            category=category,
            strategy=self.name,
        )


class MaskStrategy(AnonymizationStrategy):
    """
    Partial masking preserving format.

    Examples:
    - "jan@example.com" → "j**@e******.com"
    - "0612345678" → "06******78"
    - "Jan de Vries" → "J** ** V****"

    Options:
    - mask_char: Character to use for masking (default: "*")
    - keep_start: Characters to keep at start (default: 1)
    - keep_end: Characters to keep at end (default: 2)
    """

    name = "mask"

    def __init__(self, mask_char: str = "*", keep_start: int = 1, keep_end: int = 2):
        self.mask_char = mask_char
        self.keep_start = keep_start
        self.keep_end = keep_end

    def anonymize(self, value: str, category: str, **kwargs) -> AnonymizedValue:
        if category == "EMAIL":
            anonymized = self._mask_email(value)
        elif category == "PHONE":
            anonymized = self._mask_phone(value)
        elif category == "IBAN":
            anonymized = self._mask_iban(value)
        else:
            anonymized = self._mask_generic(value)

        return AnonymizedValue(
            original=value,
            anonymized=anonymized,
            category=category,
            strategy=self.name,
        )

    def _mask_generic(self, value: str) -> str:
        """Mask a generic value, preserving word structure."""
        words = value.split()
        masked_words = []
        for word in words:
            if len(word) <= self.keep_start + self.keep_end:
                masked_words.append(self.mask_char * len(word))
            else:
                start = word[:self.keep_start]
                end = word[-self.keep_end:] if self.keep_end > 0 else ""
                middle = self.mask_char * (len(word) - self.keep_start - self.keep_end)
                masked_words.append(start + middle + end)
        return " ".join(masked_words)

    def _mask_email(self, email: str) -> str:
        """Mask email preserving structure: j**@e******.com"""
        if "@" not in email:
            return self._mask_generic(email)

        local, domain = email.rsplit("@", 1)
        domain_parts = domain.rsplit(".", 1)

        masked_local = local[0] + self.mask_char * (len(local) - 1) if local else ""

        if len(domain_parts) == 2:
            domain_name, tld = domain_parts
            masked_domain = domain_name[0] + self.mask_char * (len(domain_name) - 1) if domain_name else ""
            return f"{masked_local}@{masked_domain}.{tld}"
        else:
            return f"{masked_local}@{self.mask_char * len(domain)}"

    def _mask_phone(self, phone: str) -> str:
        """Mask phone preserving first and last digits: 06******78"""
        digits_only = re.sub(r'\D', '', phone)
        if len(digits_only) <= 4:
            return self.mask_char * len(phone)

        # Keep first 2 and last 2 digits
        masked = digits_only[:2] + self.mask_char * (len(digits_only) - 4) + digits_only[-2:]

        # Try to preserve original formatting
        result = []
        digit_idx = 0
        for char in phone:
            if char.isdigit() and digit_idx < len(masked):
                result.append(masked[digit_idx])
                digit_idx += 1
            else:
                result.append(char)
        return "".join(result)

    def _mask_iban(self, iban: str) -> str:
        """Mask IBAN keeping country code and last 4: BE44 **** **** 5678"""
        clean = iban.replace(" ", "")
        if len(clean) < 8:
            return self.mask_char * len(iban)

        # Keep country code (2) + check digits (2) and last 4
        masked = clean[:4] + self.mask_char * (len(clean) - 8) + clean[-4:]

        # Restore spacing if original had it
        if " " in iban:
            # Add space every 4 characters
            return " ".join(masked[i:i+4] for i in range(0, len(masked), 4))
        return masked


class HashStrategy(AnonymizationStrategy):
    """
    One-way hash transformation using SHA256.

    Example: "Jan de Vries" → "a1b2c3d4e5f6..."

    Options:
    - algorithm: Hash algorithm (default: "sha256")
    - truncate: Truncate hash to N characters (default: 16)
    - salt: Optional salt for additional security
    """

    name = "hash"

    def __init__(self, algorithm: str = "sha256", truncate: int = 16, salt: str = None):
        self.algorithm = algorithm
        self.truncate = truncate
        self.salt = salt or ""

    def anonymize(self, value: str, category: str, **kwargs) -> AnonymizedValue:
        # Add salt and hash
        salted = f"{self.salt}{value}{category}"

        if self.algorithm == "sha256":
            hash_obj = hashlib.sha256(salted.encode())
        elif self.algorithm == "sha512":
            hash_obj = hashlib.sha512(salted.encode())
        elif self.algorithm == "md5":
            hash_obj = hashlib.md5(salted.encode())
        else:
            hash_obj = hashlib.sha256(salted.encode())

        hash_hex = hash_obj.hexdigest()

        if self.truncate and self.truncate < len(hash_hex):
            hash_hex = hash_hex[:self.truncate]

        return AnonymizedValue(
            original=value,
            anonymized=hash_hex,
            category=category,
            strategy=self.name,
        )


class EncryptStrategy(AnonymizationStrategy):
    """
    Reversible encryption using Fernet (AES-128-CBC).

    Example: "Jan de Vries" → "gAAAAABh..."

    This is fully reversible with the encryption key.

    Options:
    - key: Fernet key (generated if not provided)
    """

    name = "encrypt"

    def __init__(self, key: bytes = None):
        self._fernet = None
        self._key = key

    def _get_fernet(self):
        """Lazy initialization of Fernet."""
        if self._fernet is None:
            try:
                from cryptography.fernet import Fernet
            except ImportError:
                raise ImportError(
                    "cryptography not installed. Run: pip install cryptography"
                )

            if self._key is None:
                self._key = Fernet.generate_key()

            self._fernet = Fernet(self._key)
        return self._fernet

    @property
    def key(self) -> bytes:
        """Get the encryption key (generate if needed)."""
        self._get_fernet()  # Ensure key is generated
        return self._key

    def anonymize(self, value: str, category: str, **kwargs) -> AnonymizedValue:
        fernet = self._get_fernet()
        encrypted = fernet.encrypt(value.encode()).decode()

        return AnonymizedValue(
            original=value,
            anonymized=encrypted,
            category=category,
            strategy=self.name,
            metadata={"key": self._key.decode() if self._key else None}
        )

    def deanonymize(self, encrypted: str) -> str:
        """Decrypt an encrypted value."""
        fernet = self._get_fernet()
        return fernet.decrypt(encrypted.encode()).decode()

    def can_deanonymize(self) -> bool:
        return True


# Strategy registry
STRATEGIES = {
    "replace": ReplaceStrategy,
    "redact": RedactStrategy,
    "mask": MaskStrategy,
    "hash": HashStrategy,
    "encrypt": EncryptStrategy,
}


def get_strategy(name: str, **kwargs) -> AnonymizationStrategy:
    """
    Get an anonymization strategy by name.

    Args:
        name: Strategy name (replace, redact, mask, hash, encrypt)
        **kwargs: Strategy-specific options

    Returns:
        AnonymizationStrategy instance
    """
    if name not in STRATEGIES:
        raise ValueError(
            f"Unknown strategy: {name}. "
            f"Available: {', '.join(STRATEGIES.keys())}"
        )
    return STRATEGIES[name](**kwargs)
