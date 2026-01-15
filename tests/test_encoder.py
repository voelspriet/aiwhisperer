"""
Tests for DocSanitizer encoder/decoder.

Uses sample text based on patterns found in real legal documents.
"""

import pytest
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from docsanitizer import encode, decode, Mapping


# Sample text based on real document patterns (with fake data)
SAMPLE_TEXT = """
RECHTBANK VAN EERSTE AANLEG OOST-VLAANDEREN
Afdeling Dendermonde
Kabinet van onderzoeksrechter
Jan JANSSENS
Justitieplein 1
9200 Dendermonde
Tel: 052/26.08.60
jan.janssens@just.fgov.be

VERHOEK Pieter Klaas, geboren op 09/06/1998 te Lelystad, zonder gekende woon- of
verblijfplaats;

Verdacht van: Te 9130 Beveren, minstens op 16.10.2023

Er wordt sinds meerdere maanden een onderzoek gevoerd m.b.t. de invoer van een partij van
meer dan 11 ton cocaïne die op 16/10/2023 werd aangetroffen in een container in de
Antwerpse haven.

Uit de voorlopige onderzoeksresultaten blijken ernstige aanwijzingen van de betrokkenheid van
VERHOEK Pieter Klaas, zoals hiervoor nader geïdentificeerd, bij de onderzochte feiten.

DE GROOT Willem - 26-04-1993 - Wettelijke verblijfplaats: 9000 Gent,
Koningin Astridlaan 199/B000 - Nationaliteit : Belgisch

DE GROOT Karel - 18-03-1992 - Schrapping van ambtswege: 9000
Gent, Stationsstraat 756/A000 - Nationaliteit : Belgisch

Het nummer 32489667088 heeft contacten met DE GROOT Willem.
DE GROOT Jan (00/00/1952), 9000 Gent - Stationsstraat 756/A000 - vader van DE
GROOT Willem en Karel

Bankrekening: BE44 3770 8065 6345

Neem contact op via marc.politie@police.belgium.eu of +32 3 217 84 30.
"""


def test_encode_preserves_structure():
    """Test that encoding preserves document structure."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    # Structure words should be preserved
    assert "vader van" in sanitized
    assert "geboren op" in sanitized
    assert "Verdacht van" in sanitized
    assert "verblijfplaats" in sanitized
    assert "Bankrekening:" in sanitized

    # Amounts and event dates should be preserved
    assert "11 ton cocaïne" in sanitized
    assert "16/10/2023" in sanitized  # Event date, not DOB

    # Names should be replaced
    assert "VERHOEK Pieter" not in sanitized
    assert "DE GROOT Willem" not in sanitized
    assert "Jan JANSSENS" not in sanitized
    assert "PERSON_" in sanitized


def test_encode_replaces_phones():
    """Test that phone numbers are replaced."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    assert "052/26.08.60" not in sanitized
    assert "32489667088" not in sanitized
    assert "+32 3 217 84 30" not in sanitized
    assert "PHONE_" in sanitized


def test_encode_replaces_emails():
    """Test that emails are replaced."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    assert "jan.janssens@just.fgov.be" not in sanitized
    assert "marc.politie@police.belgium.eu" not in sanitized
    assert "EMAIL_" in sanitized


def test_encode_replaces_iban():
    """Test that bank accounts are replaced."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    assert "BE44 3770 8065 6345" not in sanitized
    assert "IBAN_" in sanitized


def test_encode_replaces_dob():
    """Test that dates of birth are replaced (but not event dates)."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    # DOB after "geboren op" should be replaced
    assert "09/06/1998" not in sanitized
    assert "DOB_" in sanitized

    # Event date (16/10/2023) should NOT be replaced
    assert "16/10/2023" in sanitized


def test_decode_reverses_encode():
    """Test that decode reverses encode."""
    sanitized, mapping = encode(SAMPLE_TEXT)
    decoded = decode(sanitized, mapping)

    # All original values should be back
    assert "VERHOEK Pieter Klaas" in decoded
    assert "jan.janssens@just.fgov.be" in decoded
    assert "052/26.08.60" in decoded
    assert "BE44 3770 8065 6345" in decoded


def test_consistent_placeholders():
    """Test that same value gets same placeholder."""
    text = """
    DE GROOT Willem called DE GROOT Karel.
    Later, DE GROOT Willem sent an email.
    DE GROOT Willem is the main suspect.
    """
    sanitized, mapping = encode(text)

    # Count occurrences of the placeholder for "DE GROOT Willem"
    willem_placeholder = None
    for ph, entry in mapping.entries.items():
        if "WILLEM" in entry.canonical.upper() or "Willem" in entry.canonical:
            willem_placeholder = ph
            break

    if willem_placeholder:
        # Should appear 3 times (once for each occurrence)
        assert sanitized.count(willem_placeholder) == 3


def test_relationship_preserved():
    """Test that relationship phrases are preserved."""
    text = "DE GROOT Jan is vader van DE GROOT Willem en Karel"
    sanitized, mapping = encode(text)

    # "vader van" should still be there
    assert "vader van" in sanitized
    # "en" should still be there
    assert " en " in sanitized
    # Names should be placeholders
    assert "DE GROOT" not in sanitized
    assert "PERSON_" in sanitized


def test_mapping_save_load(tmp_path):
    """Test that mapping can be saved and loaded."""
    sanitized, mapping = encode(SAMPLE_TEXT)

    # Save
    mapping_file = tmp_path / "mapping.json"
    mapping.save(mapping_file)

    # Load
    loaded = Mapping.load(mapping_file)

    # Should have same entries
    assert len(loaded.entries) == len(mapping.entries)

    # Should decode the same way
    decoded_original = decode(sanitized, mapping)
    decoded_loaded = decode(sanitized, loaded)
    assert decoded_original == decoded_loaded


def test_empty_text():
    """Test handling of empty text."""
    sanitized, mapping = encode("")
    assert sanitized == ""
    assert len(mapping.entries) == 0


def test_no_sensitive_data():
    """Test text with no sensitive data."""
    text = "This is a plain text with no sensitive information."
    sanitized, mapping = encode(text)
    assert sanitized == text
    assert len(mapping.entries) == 0


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
