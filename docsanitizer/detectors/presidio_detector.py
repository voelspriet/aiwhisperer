"""
Presidio-based PII detection.

Microsoft Presidio is a comprehensive PII detection and anonymization framework.
It combines regex patterns, NER, and context-aware detection.

Install: pip install presidio-analyzer presidio-anonymizer
Models: python -m spacy download en_core_web_lg (or other language models)
"""

from typing import List, Dict, Optional, Set
from .patterns import Match

# Presidio entity types mapped to our categories
PRESIDIO_CATEGORY_MAP = {
    # Person
    'PERSON': 'PERSON',
    'FIRST_NAME': 'PERSON',
    'LAST_NAME': 'PERSON',

    # Location
    'LOCATION': 'PLACE',
    'GPE': 'PLACE',

    # Organization
    'ORG': 'ORG',
    'ORGANIZATION': 'ORG',

    # Contact info
    'EMAIL_ADDRESS': 'EMAIL',
    'PHONE_NUMBER': 'PHONE',
    'URL': 'URL',
    'IP_ADDRESS': 'IP',

    # Financial
    'CREDIT_CARD': 'CREDIT_CARD',
    'IBAN_CODE': 'IBAN',
    'US_BANK_NUMBER': 'BANK',
    'UK_NHS': 'ID',

    # IDs
    'US_SSN': 'ID',
    'US_PASSPORT': 'ID',
    'US_DRIVER_LICENSE': 'ID',
    'UK_NHS': 'ID',
    'SG_NRIC_FIN': 'ID',
    'AU_ABN': 'ID',
    'AU_ACN': 'ID',
    'AU_TFN': 'ID',
    'AU_MEDICARE': 'ID',
    'IN_PAN': 'ID',
    'IN_AADHAAR': 'ID',
    'IN_VEHICLE_REGISTRATION': 'ID',
    'IN_VOTER': 'ID',
    'IN_PASSPORT': 'ID',

    # Dates
    'DATE_TIME': 'DATE',

    # Crypto
    'CRYPTO': 'CRYPTO',

    # Medical
    'MEDICAL_LICENSE': 'ID',
    'NRP': 'MISC',  # Nationality, religious, political group
}

# Language codes to Presidio/spaCy model mapping
LANGUAGE_MODELS = {
    'nl': 'nl_core_news_sm',
    'en': 'en_core_web_sm',
    'de': 'de_core_news_sm',
    'fr': 'fr_core_news_sm',
    'it': 'it_core_news_sm',
    'es': 'es_core_news_sm',
}


class PresidioDetector:
    """
    PII detector using Microsoft Presidio.

    Presidio combines multiple detection methods:
    - Pattern-based (regex) recognizers
    - NER-based recognizers (spaCy)
    - Context-aware detection

    Usage:
        detector = PresidioDetector()
        matches = detector.detect(text, language='en')
    """

    def __init__(self):
        self._analyzer = None
        self._available = None
        self._loaded_languages: Set[str] = set()

    @property
    def is_available(self) -> bool:
        """Check if Presidio is installed."""
        if self._available is None:
            try:
                from presidio_analyzer import AnalyzerEngine
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    def _get_analyzer(self, language: str = 'en'):
        """Get or create the Presidio analyzer for a language."""
        if not self.is_available:
            raise ImportError(
                "Presidio not installed. Run: pip install presidio-analyzer"
            )

        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Create analyzer with language support
        if self._analyzer is None or language not in self._loaded_languages:
            # Configure NLP engine for the language
            model_name = LANGUAGE_MODELS.get(language, 'en_core_web_sm')

            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": model_name}],
            }

            try:
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
                self._analyzer = AnalyzerEngine(
                    nlp_engine=nlp_engine,
                    supported_languages=[language]
                )
                self._loaded_languages.add(language)
            except Exception as e:
                # Fallback to default English
                if language != 'en':
                    print(f"Warning: Could not load {language}, falling back to English")
                    return self._get_analyzer('en')
                raise

        return self._analyzer

    def detect(
        self,
        text: str,
        language: str = 'en',
        entities: Optional[List[str]] = None,
        score_threshold: float = 0.5,
    ) -> List[Match]:
        """
        Detect PII entities in text using Presidio.

        Args:
            text: Input text
            language: Language code ('en', 'nl', 'de', etc.)
            entities: List of entity types to detect (None = all)
            score_threshold: Minimum confidence score (0-1)

        Returns:
            List of Match objects
        """
        analyzer = self._get_analyzer(language)

        # Analyze text
        results = analyzer.analyze(
            text=text,
            language=language,
            entities=entities,
            score_threshold=score_threshold,
        )

        matches = []
        for result in results:
            # Map Presidio entity type to our category
            category = PRESIDIO_CATEGORY_MAP.get(result.entity_type, 'MISC')

            matches.append(Match(
                text=text[result.start:result.end],
                start=result.start,
                end=result.end,
                category=category,
                confidence=result.score,
                context=text[max(0, result.start-20):result.end+20]
            ))

        # Sort by position
        matches.sort(key=lambda m: m.start)

        return matches

    def get_supported_entities(self, language: str = 'en') -> List[str]:
        """Get list of entity types supported by Presidio."""
        analyzer = self._get_analyzer(language)
        return analyzer.get_supported_entities(language=language)


# Global instance
_detector: Optional[PresidioDetector] = None


def get_presidio_detector() -> PresidioDetector:
    """Get the global Presidio detector instance."""
    global _detector
    if _detector is None:
        _detector = PresidioDetector()
    return _detector


def detect_with_presidio(
    text: str,
    language: str = 'en',
    score_threshold: float = 0.5,
) -> List[Match]:
    """
    Convenience function to detect PII using Presidio.

    Args:
        text: Input text
        language: Language code
        score_threshold: Minimum confidence (0-1)

    Returns:
        List of Match objects
    """
    detector = get_presidio_detector()
    return detector.detect(text, language=language, score_threshold=score_threshold)


def is_presidio_available() -> bool:
    """Check if Presidio is available."""
    return get_presidio_detector().is_available
