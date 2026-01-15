"""
NER-based detection using spaCy.

Supports multiple languages: Dutch, English, German, French, Italian, Spanish.
Uses Named Entity Recognition to detect persons, places, organizations, etc.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path

from .patterns import Match

# Language model mapping
LANGUAGE_MODELS = {
    'nl': 'nl_core_news_sm',      # Dutch
    'en': 'en_core_web_sm',       # English
    'de': 'de_core_news_sm',      # German
    'fr': 'fr_core_news_sm',      # French
    'it': 'it_core_news_sm',      # Italian
    'es': 'es_core_news_sm',      # Spanish
}

# Alternative names for languages
LANGUAGE_ALIASES = {
    'dutch': 'nl', 'nederlands': 'nl', 'flemish': 'nl', 'vlaams': 'nl',
    'english': 'en', 'engels': 'en',
    'german': 'de', 'deutsch': 'de', 'duits': 'de',
    'french': 'fr', 'français': 'fr', 'frans': 'fr',
    'italian': 'it', 'italiano': 'it', 'italiaans': 'it',
    'spanish': 'es', 'español': 'es', 'spaans': 'es',
}

# Map spaCy entity labels to our categories
# Different models use different labels, so we map them all
ENTITY_CATEGORY_MAP = {
    # Person names
    'PER': 'PERSON',
    'PERSON': 'PERSON',

    # Locations (cities, countries, regions)
    'LOC': 'PLACE',
    'GPE': 'PLACE',        # Geopolitical entities (countries, cities, states)
    'FAC': 'PLACE',        # Facilities (buildings, airports, highways)

    # Organizations
    'ORG': 'ORG',
    'ORGANIZATION': 'ORG',

    # Dates and times (we'll filter these contextually)
    'DATE': 'DATE',
    'TIME': 'TIME',

    # Miscellaneous that might be sensitive
    'MISC': 'MISC',        # Miscellaneous entities
    'PRODUCT': 'MISC',     # Products
    'EVENT': 'MISC',       # Events
    'WORK_OF_ART': 'MISC', # Titles of books, songs, etc.
    'LAW': 'MISC',         # Named documents made into laws

    # Quantities (usually not sensitive, but included for completeness)
    'MONEY': 'MONEY',
    'QUANTITY': 'MISC',
    'PERCENT': 'MISC',
    'CARDINAL': 'MISC',
    'ORDINAL': 'MISC',

    # Language-specific labels
    'NORP': 'MISC',        # Nationalities, religious, political groups
}

# Categories to include by default (skip dates, misc, money, etc.)
DEFAULT_CATEGORIES = {'PERSON', 'PLACE', 'ORG'}


class NERDetector:
    """
    Multi-language NER detector using spaCy.

    Usage:
        detector = NERDetector()
        detector.load_language('nl')  # Load Dutch model
        matches = detector.detect(text, language='nl')
    """

    def __init__(self):
        self._models: Dict[str, any] = {}
        self._spacy = None
        self._available = None

    @property
    def is_available(self) -> bool:
        """Check if spaCy is installed."""
        if self._available is None:
            try:
                import spacy
                self._spacy = spacy
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    def _normalize_language(self, lang: str) -> str:
        """Normalize language code/name to ISO code."""
        lang_lower = lang.lower().strip()
        if lang_lower in LANGUAGE_ALIASES:
            return LANGUAGE_ALIASES[lang_lower]
        if lang_lower in LANGUAGE_MODELS:
            return lang_lower
        raise ValueError(
            f"Unknown language: {lang}. "
            f"Supported: {', '.join(LANGUAGE_MODELS.keys())}"
        )

    def load_language(self, language: str) -> bool:
        """
        Load a language model.

        Args:
            language: Language code ('nl', 'en', etc.) or name ('dutch', 'english')

        Returns:
            True if loaded successfully

        Raises:
            ImportError: If spaCy is not installed
            OSError: If the language model is not installed
        """
        if not self.is_available:
            raise ImportError(
                "spaCy is not installed. Install with: pip install spacy"
            )

        lang_code = self._normalize_language(language)

        if lang_code in self._models:
            return True  # Already loaded

        model_name = LANGUAGE_MODELS[lang_code]

        try:
            self._models[lang_code] = self._spacy.load(model_name)
            return True
        except OSError:
            raise OSError(
                f"Language model '{model_name}' not installed. "
                f"Install with: python -m spacy download {model_name}"
            )

    def load_all_languages(self) -> Dict[str, bool]:
        """
        Attempt to load all supported language models.

        Returns:
            Dict mapping language code to success status
        """
        results = {}
        for lang_code in LANGUAGE_MODELS:
            try:
                self.load_language(lang_code)
                results[lang_code] = True
            except (ImportError, OSError):
                results[lang_code] = False
        return results

    def get_loaded_languages(self) -> List[str]:
        """Get list of currently loaded language codes."""
        return list(self._models.keys())

    def detect(
        self,
        text: str,
        language: str = 'nl',
        categories: Optional[Set[str]] = None,
        include_dates: bool = False,
    ) -> List[Match]:
        """
        Detect named entities in text.

        Args:
            text: Input text
            language: Language code or name
            categories: Set of categories to include (default: PERSON, PLACE, ORG)
            include_dates: Whether to include DATE entities (default: False)

        Returns:
            List of Match objects
        """
        if categories is None:
            categories = DEFAULT_CATEGORIES.copy()
            if include_dates:
                categories.add('DATE')

        lang_code = self._normalize_language(language)

        # Load language if not already loaded
        if lang_code not in self._models:
            self.load_language(lang_code)

        nlp = self._models[lang_code]
        doc = nlp(text)

        matches = []
        seen_positions: Set[Tuple[int, int]] = set()

        for ent in doc.ents:
            # Map spaCy label to our category
            category = ENTITY_CATEGORY_MAP.get(ent.label_, 'MISC')

            # Skip if not in requested categories
            if category not in categories:
                continue

            pos = (ent.start_char, ent.end_char)
            if pos in seen_positions:
                continue

            # Skip very short entities (likely false positives)
            if len(ent.text.strip()) < 2:
                continue

            # Skip entities that span multiple lines
            if '\n' in ent.text:
                continue

            seen_positions.add(pos)
            matches.append(Match(
                text=ent.text,
                start=ent.start_char,
                end=ent.end_char,
                category=category,
                confidence=0.90,  # NER is generally reliable
                context=text[max(0, ent.start_char-20):ent.end_char+20]
            ))

        return matches

    def detect_multi(
        self,
        text: str,
        languages: Optional[List[str]] = None,
        categories: Optional[Set[str]] = None,
    ) -> List[Match]:
        """
        Detect entities using multiple language models and merge results.

        Useful for documents with mixed languages.

        Args:
            text: Input text
            languages: List of language codes (default: all loaded)
            categories: Set of categories to include

        Returns:
            Merged list of Match objects (duplicates removed)
        """
        if languages is None:
            languages = self.get_loaded_languages()

        if not languages:
            raise ValueError("No languages loaded. Call load_language() first.")

        all_matches = []
        seen_positions: Set[Tuple[int, int]] = set()

        for lang in languages:
            try:
                matches = self.detect(text, language=lang, categories=categories)
                for match in matches:
                    pos = (match.start, match.end)
                    if pos not in seen_positions:
                        seen_positions.add(pos)
                        all_matches.append(match)
            except (ValueError, OSError):
                continue  # Skip languages that aren't available

        # Sort by position
        all_matches.sort(key=lambda m: m.start)

        return all_matches


# Global detector instance (lazy initialization)
_detector: Optional[NERDetector] = None


def get_detector() -> NERDetector:
    """Get the global NER detector instance."""
    global _detector
    if _detector is None:
        _detector = NERDetector()
    return _detector


def detect_entities_ner(
    text: str,
    language: str = 'nl',
    categories: Optional[Set[str]] = None,
) -> List[Match]:
    """
    Convenience function to detect entities using NER.

    Args:
        text: Input text
        language: Language code ('nl', 'en', 'de', 'fr', 'it', 'es')
        categories: Categories to detect (default: PERSON, PLACE, ORG)

    Returns:
        List of Match objects
    """
    detector = get_detector()
    return detector.detect(text, language=language, categories=categories)


def is_ner_available() -> bool:
    """Check if NER (spaCy) is available."""
    return get_detector().is_available


def get_available_languages() -> List[str]:
    """Get list of available language codes."""
    return list(LANGUAGE_MODELS.keys())


def install_language_models(languages: Optional[List[str]] = None) -> None:
    """
    Print instructions to install language models.

    Args:
        languages: List of language codes (default: all)
    """
    if languages is None:
        languages = list(LANGUAGE_MODELS.keys())

    print("To install spaCy language models, run:\n")
    print("pip install spacy\n")

    for lang in languages:
        if lang in LANGUAGE_MODELS:
            model = LANGUAGE_MODELS[lang]
            print(f"python -m spacy download {model}")

    print("\nOr install all at once:")
    models = ' '.join(LANGUAGE_MODELS[lang] for lang in languages if lang in LANGUAGE_MODELS)
    print(f"python -m spacy download {models.split()[0]}")
    for model in models.split()[1:]:
        print(f"python -m spacy download {model}")
