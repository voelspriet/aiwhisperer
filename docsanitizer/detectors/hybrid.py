"""
Hybrid detector combining spaCy NER with pattern-based detection.

Best of both worlds:
- spaCy: Names, locations, organizations (context-aware)
- Patterns: Email, phone, IBAN, BSN, dates (structured data)

This is the recommended detector for production use.
"""

import re
from typing import List, Set, Tuple, Optional
from dataclasses import dataclass

from .patterns import (
    Match,
    detect_phones,
    detect_emails,
    detect_ibans,
    detect_dates_of_birth,
    detect_national_ids,
    detect_roads,
    detect_context_places,
    detect_any_street,
    detect_vehicles,
    detect_names_by_context,
)

# Language model mapping
LANGUAGE_MODELS = {
    'nl': 'nl_core_news_sm',
    'en': 'en_core_web_sm',
    'de': 'de_core_news_sm',
    'fr': 'fr_core_news_sm',
    'it': 'it_core_news_sm',
    'es': 'es_core_news_sm',
}

# Map spaCy labels to our categories
SPACY_LABEL_MAP = {
    # Person
    'PER': 'PERSON',
    'PERSON': 'PERSON',

    # Location
    'LOC': 'PLACE',
    'GPE': 'PLACE',
    'FAC': 'PLACE',

    # Organization
    'ORG': 'ORG',

    # Misc (usually skip)
    'MISC': 'MISC',
    'NORP': 'MISC',
    'EVENT': 'MISC',
    'PRODUCT': 'MISC',
    'WORK_OF_ART': 'MISC',
}

# Categories to include from spaCy (skip MISC by default)
SPACY_CATEGORIES = {'PERSON', 'PLACE', 'ORG'}


class HybridDetector:
    """
    Hybrid PII detector combining spaCy NER with pattern matching.

    Usage:
        detector = HybridDetector()
        matches = detector.detect(text, language='nl')
    """

    def __init__(self):
        self._models = {}
        self._spacy = None

    def _load_spacy(self):
        """Load spaCy module."""
        if self._spacy is None:
            try:
                import spacy
                self._spacy = spacy
            except ImportError:
                raise ImportError(
                    "spaCy not installed. Run: pip install spacy"
                )
        return self._spacy

    def _get_model(self, language: str):
        """Get or load spaCy model for language."""
        if language not in self._models:
            spacy = self._load_spacy()
            model_name = LANGUAGE_MODELS.get(language, 'en_core_web_sm')

            try:
                self._models[language] = spacy.load(model_name)
            except OSError:
                raise OSError(
                    f"Language model '{model_name}' not installed. "
                    f"Run: python -m spacy download {model_name}"
                )

        return self._models[language]

    def detect(
        self,
        text: str,
        language: str = 'nl',
        include_org: bool = False,
        chunk_size: int = 500000,
    ) -> List[Match]:
        """
        Detect PII using hybrid approach.

        Args:
            text: Input text
            language: Language code (nl, en, de, fr, it, es)
            include_org: Include organizations (default: False)
            chunk_size: Max characters per chunk for spaCy (default: 500K)

        Returns:
            List of Match objects
        """
        all_matches = []
        seen_positions: Set[Tuple[int, int]] = set()

        # =================================================================
        # STEP 1: Pattern-based detection for structured data
        # =================================================================
        # These patterns are very reliable for structured data
        all_matches.extend(detect_emails(text))
        all_matches.extend(detect_phones(text))
        all_matches.extend(detect_ibans(text))
        all_matches.extend(detect_dates_of_birth(text))
        all_matches.extend(detect_national_ids(text))
        all_matches.extend(detect_vehicles(text))        # Fiat Ducato, BMW, Mercedes
        all_matches.extend(detect_roads(text))           # N133, A12, E19
        all_matches.extend(detect_any_street(text))      # Kampweg, Noorderlaan
        all_matches.extend(detect_context_places(text))  # "te Wuustwezel"
        all_matches.extend(detect_names_by_context(text)) # Names before dates, ALLCAPS

        # Track positions of pattern matches
        for m in all_matches:
            seen_positions.add((m.start, m.end))

        # =================================================================
        # STEP 2: spaCy NER for names and locations
        # =================================================================
        nlp = self._get_model(language)

        # Process in chunks if text is too large
        if len(text) > chunk_size:
            ner_matches = self._process_in_chunks(text, nlp, chunk_size)
        else:
            ner_matches = self._extract_ner_entities(text, nlp, 0)

        categories_to_include = {'PERSON', 'PLACE'}
        if include_org:
            categories_to_include.add('ORG')

        for ent_text, start, end, label in ner_matches:
            # Map spaCy label to our category
            category = SPACY_LABEL_MAP.get(label)
            if category not in categories_to_include:
                continue

            pos = (start, end)

            # Skip if overlaps with pattern match (patterns win for structured data)
            if self._overlaps_any(pos, seen_positions):
                continue

            # Skip very short entities
            if len(ent_text.strip()) < 2:
                continue

            # Skip if it looks like an email (spaCy sometimes misclassifies)
            if '@' in ent_text or ent_text.lower() == 'email':
                continue

            seen_positions.add(pos)
            all_matches.append(Match(
                text=ent_text,
                start=start,
                end=end,
                category=category,
                confidence=0.90,
                context=text[max(0, start-20):end+20]
            ))

        # Sort by position
        all_matches.sort(key=lambda m: m.start)

        return all_matches

    def _extract_ner_entities(self, text: str, nlp, offset: int) -> List[tuple]:
        """Extract NER entities from text, returning (text, start, end, label) tuples."""
        doc = nlp(text)
        return [
            (ent.text, ent.start_char + offset, ent.end_char + offset, ent.label_)
            for ent in doc.ents
        ]

    def _process_in_chunks(self, text: str, nlp, chunk_size: int) -> List[tuple]:
        """Process large text in chunks, splitting at paragraph boundaries."""
        all_entities = []

        # Split into chunks at paragraph boundaries
        chunks = []
        current_pos = 0

        while current_pos < len(text):
            # Find end of chunk
            chunk_end = min(current_pos + chunk_size, len(text))

            # If not at end, find a good break point (paragraph or sentence)
            if chunk_end < len(text):
                # Look for paragraph break
                para_break = text.rfind('\n\n', current_pos, chunk_end)
                if para_break > current_pos + chunk_size // 2:
                    chunk_end = para_break + 2
                else:
                    # Look for sentence break
                    sent_break = text.rfind('. ', current_pos, chunk_end)
                    if sent_break > current_pos + chunk_size // 2:
                        chunk_end = sent_break + 2

            chunks.append((current_pos, chunk_end))
            current_pos = chunk_end

        # Process each chunk
        for start_offset, end_offset in chunks:
            chunk_text = text[start_offset:end_offset]
            entities = self._extract_ner_entities(chunk_text, nlp, start_offset)
            all_entities.extend(entities)

        return all_entities

    def _overlaps_any(
        self,
        pos: Tuple[int, int],
        positions: Set[Tuple[int, int]]
    ) -> bool:
        """Check if position overlaps with any existing position."""
        start, end = pos
        for existing_start, existing_end in positions:
            # Check overlap
            if not (end <= existing_start or start >= existing_end):
                return True
        return False


# Global instance
_detector: Optional[HybridDetector] = None


def get_hybrid_detector() -> HybridDetector:
    """Get global hybrid detector instance."""
    global _detector
    if _detector is None:
        _detector = HybridDetector()
    return _detector


def detect_hybrid(
    text: str,
    language: str = 'nl',
    include_org: bool = False,
) -> List[Match]:
    """
    Detect PII using hybrid approach (recommended).

    Combines:
    - spaCy NER for names and locations
    - Pattern matching for email, phone, IBAN, BSN, dates

    Args:
        text: Input text
        language: Language code (nl, en, de, fr, it, es)
        include_org: Include organizations

    Returns:
        List of Match objects
    """
    return get_hybrid_detector().detect(text, language=language, include_org=include_org)
