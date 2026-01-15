"""
Decoder - Replace placeholders back to original values.

The decoder:
1. Finds all placeholders in text (PERSON_001, PHONE_002, etc.)
2. Looks up original values in the mapping
3. Replaces placeholders with original values
4. Returns the decoded text
"""

import re
from typing import Optional, Union
from pathlib import Path

from .mapper import Mapping


# Pattern to match placeholders: CATEGORY_NNN (3-4 digits)
# All categories: PERSON, PHONE, EMAIL, ADDRESS, IBAN, DOB, ID, ORG, PLACE, STREET, ROAD, VEHICLE
PLACEHOLDER_PATTERN = r'\b(PERSON|PHONE|EMAIL|ADDRESS|IBAN|DOB|ID|ORG|PLACE|LOCATION|STREET|ROAD|VEHICLE)_(\d{3,4})\b'


def decode(text: str, mapping: Mapping) -> str:
    """
    Decode placeholders back to original values.

    Args:
        text: Text containing placeholders (e.g., from AI output)
        mapping: The mapping used during encoding

    Returns:
        Text with placeholders replaced by original values

    Example:
        >>> text = "PERSON_001 is vader van PERSON_002"
        >>> decoded = decode(text, mapping)
        >>> print(decoded)
        "El Mansouri Mohand is vader van El Mansouri Brahim"
    """
    def replace_placeholder(match):
        placeholder = match.group(0)
        original = mapping.get_original(placeholder)
        return original if original else placeholder

    return re.sub(PLACEHOLDER_PATTERN, replace_placeholder, text)


def decode_file(
    input_path: Union[str, Path],
    mapping_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    encoding: str = 'utf-8'
) -> str:
    """
    Decode a file using a mapping.

    Args:
        input_path: Path to file with placeholders (e.g., AI output)
        mapping_path: Path to mapping JSON file
        output_path: Path for decoded output (optional)
        encoding: File encoding (default utf-8)

    Returns:
        Decoded text
    """
    # Load mapping
    mapping = Mapping.load(mapping_path)

    # Read input
    with open(input_path, 'r', encoding=encoding) as f:
        text = f.read()

    # Decode
    decoded = decode(text, mapping)

    # Save if path provided
    if output_path:
        with open(output_path, 'w', encoding=encoding) as f:
            f.write(decoded)

    return decoded


def find_placeholders(text: str) -> list:
    """Find all placeholders in text (useful for debugging)."""
    return re.findall(PLACEHOLDER_PATTERN, text)


def validate_decode(original: str, sanitized: str, decoded: str) -> dict:
    """
    Validate that decode reversed the encode correctly.

    Returns dict with validation results.
    """
    results = {
        "original_length": len(original),
        "sanitized_length": len(sanitized),
        "decoded_length": len(decoded),
        "lengths_match": len(original) == len(decoded),
        "content_match": original == decoded,
    }

    if not results["content_match"]:
        # Find first difference
        for i, (a, b) in enumerate(zip(original, decoded)):
            if a != b:
                results["first_diff_position"] = i
                results["first_diff_original"] = original[max(0,i-20):i+20]
                results["first_diff_decoded"] = decoded[max(0,i-20):i+20]
                break

    return results
