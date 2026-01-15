"""
GLiNER-based zero-shot NER detection.

GLiNER (Generalist Language-Independent NER) can detect ANY entity type
without retraining - you simply specify the labels you want to detect.

This is powerful for PII detection because:
1. Works across multiple languages
2. No need to train for new entity types
3. Can be customized on-the-fly
4. Runs locally (no API calls)

Models:
- urchade/gliner_multi_pii-v1: Multi-language PII detection
- knowledgator/gliner-pii-base-v1.0: Best F1 score (80.99%)
- knowledgator/gliner-pii-edge-v1.0: Optimized for speed

Install: pip install gliner
"""

from typing import List, Dict, Optional, Set
from .patterns import Match

# Default PII labels to detect
DEFAULT_PII_LABELS = [
    "person",
    "organization",
    "phone number",
    "address",
    "email",
    "credit card number",
    "social security number",
    "passport number",
    "driver's license number",
    "bank account number",
    "date of birth",
    "location",
    "city",
    "street",
]

# Extended labels for comprehensive detection
EXTENDED_PII_LABELS = DEFAULT_PII_LABELS + [
    "health insurance id",
    "medical record number",
    "tax id",
    "national id",
    "vehicle registration",
    "ip address",
    "username",
    "password",
    "api key",
    "license plate",
]

# Map GLiNER labels to our categories
GLINER_CATEGORY_MAP = {
    # Person
    "person": "PERSON",
    "name": "PERSON",
    "first name": "PERSON",
    "last name": "PERSON",

    # Location
    "location": "PLACE",
    "city": "PLACE",
    "country": "PLACE",
    "state": "PLACE",
    "address": "ADDRESS",
    "street": "STREET",

    # Organization
    "organization": "ORG",
    "company": "ORG",

    # Contact
    "phone number": "PHONE",
    "email": "EMAIL",
    "email address": "EMAIL",
    "ip address": "IP",
    "url": "URL",

    # Financial
    "credit card number": "CREDIT_CARD",
    "bank account number": "IBAN",
    "iban": "IBAN",

    # IDs
    "social security number": "ID",
    "passport number": "ID",
    "driver's license number": "ID",
    "national id": "ID",
    "tax id": "ID",
    "health insurance id": "ID",
    "medical record number": "ID",
    "vehicle registration": "ID",
    "license plate": "ID",

    # Dates
    "date of birth": "DOB",
    "date": "DATE",

    # Credentials
    "username": "CREDENTIAL",
    "password": "CREDENTIAL",
    "api key": "CREDENTIAL",
}

# Available pre-trained PII models
PII_MODELS = {
    "multi-pii": "urchade/gliner_multi_pii-v1",
    "base": "knowledgator/gliner-pii-base-v1.0",
    "small": "knowledgator/gliner-pii-small-v1.0",
    "large": "knowledgator/gliner-pii-large-v1.0",
    "edge": "knowledgator/gliner-pii-edge-v1.0",
    "gretel-small": "gretelai/gretel-gliner-bi-small-v1.0",
    "gretel-base": "gretelai/gretel-gliner-bi-base-v1.0",
}


class GLiNERDetector:
    """
    Zero-shot NER detector using GLiNER.

    GLiNER can detect any entity type you specify, making it extremely
    flexible for PII detection across languages and domains.

    Usage:
        detector = GLiNERDetector()
        detector.load_model()  # or load_model("base") for PII-specific model

        # Detect with default PII labels
        matches = detector.detect(text)

        # Detect with custom labels
        matches = detector.detect(text, labels=["person", "company", "product"])
    """

    def __init__(self):
        self._model = None
        self._model_name = None
        self._available = None
        self._gliner = None

    @property
    def is_available(self) -> bool:
        """Check if GLiNER is installed."""
        if self._available is None:
            try:
                from gliner import GLiNER
                self._gliner = GLiNER
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    def load_model(self, model: str = "multi-pii") -> None:
        """
        Load a GLiNER model.

        Args:
            model: Model name or key from PII_MODELS
                   - "multi-pii": Multi-language PII (default)
                   - "base": Best accuracy
                   - "edge": Fastest
                   - Or full HuggingFace model path
        """
        if not self.is_available:
            raise ImportError(
                "GLiNER not installed. Run: pip install gliner"
            )

        # Resolve model name
        model_path = PII_MODELS.get(model, model)

        if self._model is not None and self._model_name == model_path:
            return  # Already loaded

        print(f"Loading GLiNER model: {model_path}...")
        self._model = self._gliner.from_pretrained(model_path)
        self._model_name = model_path
        print(f"Model loaded successfully.")

    def detect(
        self,
        text: str,
        labels: Optional[List[str]] = None,
        threshold: float = 0.5,
        flat_ner: bool = True,
    ) -> List[Match]:
        """
        Detect entities in text.

        Args:
            text: Input text
            labels: Entity labels to detect (default: DEFAULT_PII_LABELS)
            threshold: Minimum confidence score (0-1)
            flat_ner: If True, no overlapping entities

        Returns:
            List of Match objects
        """
        if self._model is None:
            self.load_model()

        if labels is None:
            labels = DEFAULT_PII_LABELS

        # Run prediction
        entities = self._model.predict_entities(
            text,
            labels,
            threshold=threshold,
            flat_ner=flat_ner,
        )

        matches = []
        for ent in entities:
            # Map label to our category
            label_lower = ent["label"].lower()
            category = GLINER_CATEGORY_MAP.get(label_lower, "MISC")

            # Find position in text
            start = ent["start"]
            end = ent["end"]
            entity_text = ent["text"]

            matches.append(Match(
                text=entity_text,
                start=start,
                end=end,
                category=category,
                confidence=ent["score"],
                context=text[max(0, start-20):end+20]
            ))

        # Sort by position
        matches.sort(key=lambda m: m.start)

        return matches

    def detect_pii(
        self,
        text: str,
        extended: bool = False,
        threshold: float = 0.5,
    ) -> List[Match]:
        """
        Detect PII with predefined labels.

        Args:
            text: Input text
            extended: Use extended PII labels (more comprehensive)
            threshold: Minimum confidence score

        Returns:
            List of Match objects
        """
        labels = EXTENDED_PII_LABELS if extended else DEFAULT_PII_LABELS
        return self.detect(text, labels=labels, threshold=threshold)


# Global instance
_detector: Optional[GLiNERDetector] = None


def get_gliner_detector() -> GLiNERDetector:
    """Get the global GLiNER detector instance."""
    global _detector
    if _detector is None:
        _detector = GLiNERDetector()
    return _detector


def detect_with_gliner(
    text: str,
    labels: Optional[List[str]] = None,
    threshold: float = 0.5,
) -> List[Match]:
    """
    Convenience function to detect entities using GLiNER.

    Args:
        text: Input text
        labels: Entity labels to detect
        threshold: Minimum confidence

    Returns:
        List of Match objects
    """
    detector = get_gliner_detector()
    return detector.detect(text, labels=labels, threshold=threshold)


def is_gliner_available() -> bool:
    """Check if GLiNER is available."""
    return get_gliner_detector().is_available
