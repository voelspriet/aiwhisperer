"""
Pattern detection for sensitive data.

Based on analysis of real legal documents (Belgian criminal investigations).
Patterns are designed to catch variations while preserving document structure.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class Match:
    """A detected sensitive value."""
    text: str           # The actual text found
    start: int          # Start position in document
    end: int            # End position in document
    category: str       # PERSON, PHONE, EMAIL, etc.
    confidence: float   # 0.0 to 1.0
    context: str = ""   # Surrounding text for debugging


# =============================================================================
# PHONE NUMBER PATTERNS
# =============================================================================

PHONE_PATTERNS = [
    # === BELGIAN ===
    # Belgian landline: 052/26.08.60, 03/217.81.11
    (r'\b0\d{1,2}[/.\s]\d{2,3}[/.\s]\d{2}[/.\s]\d{2}\b', 'BE_LANDLINE'),
    # Belgian mobile international: 32489667088, +32 489 66 70 88
    (r'\+?32\s?\d{9}', 'BE_MOBILE'),
    (r'\+?32\s?\d{3}\s?\d{2}\s?\d{2}\s?\d{2}', 'BE_MOBILE'),
    # Belgian mobile local: 0489/66.70.88, 0489 66 70 88
    (r'\b0[4-9]\d{2}[/.\s]?\d{2}[/.\s]?\d{2}[/.\s]?\d{2}\b', 'BE_MOBILE_LOCAL'),

    # === DUTCH ===
    (r'\+?31\s?\d{9}', 'NL_MOBILE'),
    (r'\+?31\s?6\s?\d{4}\s?\d{4}', 'NL_MOBILE'),

    # === US/CANADA ===
    # (555) 123-4567, 555-123-4567, 555.123.4567
    (r'\(\d{3}\)\s?\d{3}[-.\s]?\d{4}', 'US_PHONE'),
    (r'\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b', 'US_PHONE'),
    # +1 555 123 4567, 1-555-123-4567
    (r'\+?1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}', 'US_PHONE'),

    # === UK ===
    # +44 20 7946 0958, 020 7946 0958
    (r'\+?44\s?\d{2,4}\s?\d{3,4}\s?\d{4}', 'UK_PHONE'),
    (r'\b0\d{2,4}\s?\d{3,4}\s?\d{4}\b', 'UK_PHONE'),

    # === FRENCH ===
    # +33 1 23 45 67 89, 01 23 45 67 89
    (r'\+?33\s?\d{9}', 'FR_MOBILE'),
    (r'\+?33\s?\d\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}', 'FR_PHONE'),
    (r'\b0\d\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{2}\b', 'FR_PHONE'),

    # === GERMAN ===
    # +49 30 12345678, 030 12345678
    (r'\+?49\s?\d{2,4}\s?\d{6,8}', 'DE_PHONE'),
    (r'\b0\d{2,4}\s?\d{6,8}\b', 'DE_PHONE'),

    # === OTHER ===
    # Moroccan: 212654549112
    (r'\+?212\s?\d{9}', 'MA_MOBILE'),
    # Russian: 79541101008
    (r'\+?79\s?\d{9}', 'RU_MOBILE'),
    # Generic international with + prefix
    (r'\+\d{2,3}\s?\d{8,12}', 'INTL_GENERIC'),
]


def detect_phones(text: str) -> List[Match]:
    """Detect phone numbers in text."""
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern, subtype in PHONE_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                seen_positions.add(pos)
                matches.append(Match(
                    text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    category='PHONE',
                    confidence=0.95,
                    context=text[max(0, m.start()-20):m.end()+20]
                ))

    return matches


# =============================================================================
# EMAIL PATTERNS
# =============================================================================

EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


def detect_emails(text: str) -> List[Match]:
    """Detect email addresses in text."""
    matches = []

    for m in re.finditer(EMAIL_PATTERN, text):
        matches.append(Match(
            text=m.group(),
            start=m.start(),
            end=m.end(),
            category='EMAIL',
            confidence=0.99,
            context=text[max(0, m.start()-20):m.end()+20]
        ))

    return matches


# =============================================================================
# IBAN / BANK ACCOUNT PATTERNS
# =============================================================================

IBAN_PATTERNS = [
    # Belgian IBAN: BE44 3770 8065 6345 or BE44377080656345
    r'\bBE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\b',

    # Dutch IBAN: NL91ABNA0417164300
    r'\bNL\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b',

    # German IBAN: DE89 3704 0044 0532 0130 00
    r'\bDE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b',

    # French IBAN: FR76 3000 6000 0112 3456 7890 189
    r'\bFR\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b',

    # UK IBAN: GB29 NWBK 6016 1331 9268 19
    r'\bGB\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b',

    # Spanish IBAN: ES91 2100 0418 4502 0005 1332
    r'\bES\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',

    # Italian IBAN: IT60 X054 2811 1010 0000 0123 456
    r'\bIT\d{2}\s?[A-Z]\d{3}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b',

    # Generic European IBAN (2 letter country + 2 digits + up to 30 alphanumeric)
    r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?[A-Z0-9]{4}){2,6}\b',
]


def detect_ibans(text: str) -> List[Match]:
    """Detect bank account numbers (IBAN) in text."""
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern in IBAN_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                # Skip if contains XX (already masked)
                if 'XX' in m.group() or 'xx' in m.group():
                    continue
                seen_positions.add(pos)
                matches.append(Match(
                    text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    category='IBAN',
                    confidence=0.95,
                    context=text[max(0, m.start()-20):m.end()+20]
                ))

    return matches


# =============================================================================
# DATE OF BIRTH PATTERNS (Context-Aware)
# =============================================================================

DATE_PATTERN = r'\b\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4}\b'

# Context words that indicate a date is a DOB (not an event date) - multi-language
DOB_CONTEXT_BEFORE = [
    # Dutch/Belgian
    'geboren op', 'geboren', 'geboortedatum', 'geboortedatum:',
    # English
    'birth', 'date of birth', 'dob', 'born on', 'born',
    # French
    'né le', 'née le', 'naissance', 'date de naissance',
    # German
    'geboren am', 'geburtsdatum', 'geb.',
    # Symbols
    '°', '*',
]

DOB_CONTEXT_AFTER = [
    'te ', 'in ', 'at ', 'à ',
]


def detect_dates_of_birth(text: str) -> List[Match]:
    """
    Detect dates of birth (not event dates).

    Uses context to distinguish:
    - "geboren op 26/04/1993" → DOB (replace)
    - "aangetroffen op 16/10/2023" → Event date (keep)
    """
    matches = []
    text_lower = text.lower()

    for m in re.finditer(DATE_PATTERN, text):
        # Look at context before the date
        start_context = max(0, m.start() - 30)
        before = text_lower[start_context:m.start()]

        # Check if this looks like a DOB
        is_dob = any(ctx in before for ctx in DOB_CONTEXT_BEFORE)

        if is_dob:
            matches.append(Match(
                text=m.group(),
                start=m.start(),
                end=m.end(),
                category='DOB',
                confidence=0.90,
                context=text[max(0, m.start()-30):m.end()+20]
            ))

    return matches


# =============================================================================
# ADDRESS PATTERNS
# =============================================================================

# Context words before addresses (multi-language)
ADDRESS_CONTEXT = [
    # Dutch/Belgian
    'woonplaats', 'verblijfplaats', 'adres', 'wonende', 'gevestigd',
    # English
    'residing', 'address', 'located at', 'lives at', 'living at',
    # French
    'domicile', 'résidence', 'adresse', 'demeurant',
    # German
    'wohnhaft', 'anschrift', 'adresse',
]

# Address patterns (multi-language)
ADDRESS_PATTERNS = [
    # === BELGIAN ===
    # Full Belgian address with apartment: Streetname 123/A000
    r'[A-Z][a-zé]+(?:straat|laan|weg|plein|singel|dreef|lei|steenweg|kaai)[a-z]*\s+\d+(?:/[A-Z]?\d+)?',
    # Belgian postal code + city: 9000 Gent
    r'\b[1-9]\d{3} [A-Z][a-z]+\b',

    # === DUTCH ===
    # Dutch postal code + city: 3011 HE Rotterdam
    r'\b\d{4}\s?[A-Z]{2}\s+[A-Z][a-z]+(?:\s+\([A-Za-z]+\))?',

    # === US ===
    # 123 Main Street, 456 Oak Avenue, 789 First Ave
    r'\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct|Place|Pl)\b',
    # US ZIP code: 12345 or 12345-6789
    r'\b\d{5}(?:-\d{4})?\b',
    # City, ST 12345 pattern
    r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?\b',

    # === UK ===
    # UK postcode: SW1A 1AA, EC1A 1BB, W1A 0AX
    r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b',
    # 123 High Street, London
    r'\b\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+(?:Street|Road|Lane|Avenue|Gardens|Square|Terrace|Close|Crescent)\b',

    # === FRENCH ===
    # 123 rue de la Paix, 45 avenue des Champs-Élysées
    r'\b\d+\s+(?:rue|avenue|boulevard|place|allée|chemin|impasse)\s+(?:de\s+(?:la\s+)?|du\s+|des\s+)?[A-Z][a-zé-]+(?:\s+[A-Z][a-zé-]+)*\b',
    # French postal code + city: 75001 Paris
    r'\b\d{5}\s+[A-Z][a-zé-]+(?:-[A-Z][a-zé-]+)*\b',

    # === GERMAN ===
    # Hauptstraße 123, Berliner Straße 45
    r'\b[A-Z][a-zäöüß]+(?:straße|strasse|weg|platz|allee|gasse)\s+\d+[a-z]?\b',
    # German postal code + city: 10115 Berlin
    r'\b\d{5}\s+[A-Z][a-zäöüß]+\b',
]


def detect_addresses(text: str) -> List[Match]:
    """Detect physical addresses in text."""
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern in ADDRESS_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                # Skip if match contains newlines (spans logical lines)
                if '\n' in m.group():
                    continue
                seen_positions.add(pos)
                matches.append(Match(
                    text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    category='ADDRESS',
                    confidence=0.85,
                    context=text[max(0, m.start()-30):m.end()+20]
                ))

    return matches


# =============================================================================
# NATIONAL ID PATTERNS
# =============================================================================

# National ID patterns (multi-country)
NATIONAL_ID_PATTERNS = [
    # === DUTCH ===
    # BSN (Burgerservicenummer): 9 digits, e.g., 123456789 or 12345678-9
    # Note: Real BSN validation requires 11-proef checksum
    (r'\b\d{9}\b', 'NL_BSN'),
    (r'\b\d{8}[-.\s]?\d{1}\b', 'NL_BSN'),

    # === BELGIAN ===
    # Belgian national number (Rijksregisternummer): 93.04.26-123.45 or 93042612345
    (r'\b\d{2}\.?\d{2}\.?\d{2}[-.\s]?\d{3}[-.\s]?\d{2}\b', 'BE_NATIONAL'),

    # === US ===
    # SSN: 123-45-6789 or 123 45 6789
    (r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', 'US_SSN'),

    # === UK ===
    # National Insurance: AB 12 34 56 C or AB123456C
    (r'\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b', 'UK_NI'),

    # === FRENCH ===
    # INSEE/Social Security: 1 85 12 75 108 123 45
    (r'\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b', 'FR_INSEE'),

    # === GERMAN ===
    # Sozialversicherungsnummer: 12 150485 A 123 4
    (r'\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\s?\d\b', 'DE_SOZVERS'),
    # Personalausweisnummer: L12345678 (1 letter + 8 digits)
    (r'\b[A-Z]\d{8}\b', 'DE_PERSO'),

    # === SPANISH ===
    # DNI: 12345678-A or 12345678A
    (r'\b\d{8}[-\s]?[A-Z]\b', 'ES_DNI'),
    # NIE (foreigners): X-1234567-A
    (r'\b[XYZ][-\s]?\d{7}[-\s]?[A-Z]\b', 'ES_NIE'),

    # === ITALIAN ===
    # Codice Fiscale: RSSMRA85M01H501Z (16 alphanumeric)
    (r'\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b', 'IT_CF'),

    # === PASSPORT NUMBERS ===
    # Generic passport (usually 8-9 alphanumeric)
    (r'\b[A-Z]{1,2}\d{6,8}\b', 'PASSPORT'),
]

# Context required for ambiguous patterns (to avoid false positives)
ID_CONTEXT = [
    # Dutch
    'bsn', 'burgerservicenummer', 'sofinummer', 'sofi-nummer',
    # Belgian
    'nationaal nummer', 'rijksregisternummer', 'identiteitskaartnummer',
    'national number', 'id number',
    # English
    'ssn', 'social security', 'national insurance', 'ni number',
    'passport', 'driver license', 'driving licence',
    # French
    'numéro de sécurité sociale', 'numéro insee', 'passeport',
    # German
    'sozialversicherungsnummer', 'personalausweis', 'reisepass',
    # Spanish
    'dni', 'nie', 'documento nacional',
    # Italian
    'codice fiscale',
]


def _validate_bsn(bsn: str) -> bool:
    """
    Validate Dutch BSN using the 11-proef (11-check).

    The BSN is valid if:
    - 9 digits
    - Sum of (digit[i] * weight[i]) is divisible by 11
    - Weights are: 9, 8, 7, 6, 5, 4, 3, 2, -1
    """
    digits = re.sub(r'\D', '', bsn)
    if len(digits) != 9:
        return False

    weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 11 == 0


def detect_national_ids(text: str) -> List[Match]:
    """Detect national ID numbers (requires context for ambiguous patterns)."""
    matches = []
    text_lower = text.lower()
    seen_positions: Set[tuple] = set()

    for pattern, subtype in NATIONAL_ID_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            if pos in seen_positions:
                continue

            # Check context for ambiguous patterns
            start_context = max(0, m.start() - 50)
            before = text_lower[start_context:m.start()]
            has_context = any(ctx in before for ctx in ID_CONTEXT)

            # Dutch BSN: validate with 11-proef OR require context
            if subtype == 'NL_BSN':
                if not _validate_bsn(m.group()) and not has_context:
                    continue

            # SSN pattern is very common - require strong context
            if subtype == 'US_SSN':
                if not any(ctx in before for ctx in ['ssn', 'social security']):
                    continue

            # Belgian 11-digit numbers need context
            if subtype == 'BE_NATIONAL':
                digits = m.group().replace('.', '').replace('-', '').replace(' ', '')
                if len(digits) == 11 and not has_context:
                    continue

            # Passport numbers are ambiguous - require context
            if subtype == 'PASSPORT' and not has_context:
                continue

            seen_positions.add(pos)
            matches.append(Match(
                text=m.group(),
                start=m.start(),
                end=m.end(),
                category='ID',
                confidence=0.85 if has_context else 0.70,
                context=text[max(0, m.start()-30):m.end()+20]
            ))

    return matches


# =============================================================================
# PLACE NAME PATTERNS (Cities, Towns)
# =============================================================================

# Major Belgian cities and towns
BELGIAN_PLACES = {
    # Flemish Region
    'Antwerpen', 'Gent', 'Brugge', 'Leuven', 'Mechelen', 'Aalst', 'Hasselt',
    'Sint-Niklaas', 'Kortrijk', 'Oostende', 'Genk', 'Roeselare', 'Dendermonde',
    'Turnhout', 'Lokeren', 'Beveren', 'Vilvoorde', 'Waregem', 'Ieper',
    'Herentals', 'Diest', 'Tongeren', 'Lommel', 'Tienen', 'Maasmechelen',
    'Geraardsbergen', 'Ninove', 'Wetteren', 'Brasschaat', 'Beringen',
    'Temse', 'Knokke-Heist', 'Mol', 'Aarschot', 'Izegem', 'Eeklo',
    'Deinze', 'Halle', 'Dilsen-Stokkem', 'Pelt', 'Zottegem', 'Oudenaarde',
    'Menen', 'Willebroek', 'Zele', 'Wevelgem', 'Bree', 'Bornem',
    # Brussels Region
    'Brussel', 'Brussels', 'Bruxelles', 'Schaarbeek', 'Anderlecht', 'Molenbeek',
    'Etterbeek', 'Elsene', 'Ixelles', 'Ukkel', 'Uccle', 'Jette', 'Evere',
    'Sint-Gillis', 'Sint-Jans-Molenbeek', 'Vorst', 'Forest', 'Watermaal-Bosvoorde',
    # Walloon Region
    'Luik', 'Liège', 'Charleroi', 'Namen', 'Namur', 'Bergen', 'Mons',
    'La Louvière', 'Doornik', 'Tournai', 'Seraing', 'Verviers', 'Moeskroen',
    'Châtelet', 'Binche', 'Soignies', 'Ath', 'Eupen', 'Malmedy', 'Arlon',
    # Other commonly used
    'Zaventem', 'Mortsel', 'Boom', 'Kapellen', 'Schoten', 'Wijnegem',
    'Merksem', 'Deurne', 'Berchem', 'Hoboken', 'Borgerhout', 'Wilrijk',
}

# Major Dutch cities
DUTCH_PLACES = {
    'Amsterdam', 'Rotterdam', 'Den Haag', "'s-Gravenhage", 'Utrecht',
    'Eindhoven', 'Tilburg', 'Groningen', 'Almere', 'Breda', 'Nijmegen',
    'Enschede', 'Apeldoorn', 'Haarlem', 'Arnhem', 'Zaanstad', 'Amersfoort',
    'Haarlemmermeer', 'Dordrecht', 'Leiden', 'Zoetermeer', 'Maastricht',
    'Delft', 'Deventer', 'Alkmaar', 'Venlo', 'Hilversum', 'Heerlen',
    'Roosendaal', 'Oss', 'Schiedam', 'Spijkenisse', 'Helmond',
}

# German cities near borders (commonly appear in Belgian/Dutch documents)
GERMAN_PLACES = {
    'Aken', 'Aachen', 'Keulen', 'Köln', 'Düsseldorf', 'Dusseldorf',
    'Bonn', 'Duisburg', 'Essen', 'Mönchengladbach',
}

# Combine all known places
KNOWN_PLACES = BELGIAN_PLACES | DUTCH_PLACES | GERMAN_PLACES

# Context words that indicate a place name follows
PLACE_CONTEXT_BEFORE = [
    # Dutch/Belgian
    'te ', 'in ', 'naar ', 'uit ', 'van ', 'bij ', 'nabij ',
    'geboren te', 'wonende te', 'gevestigd te', 'afkomstig uit',
    'woonachtig te', 'verblijvende te',
    # English
    'in ', 'at ', 'from ', 'to ', 'near ',
    'born in', 'residing in', 'located in',
    # French
    'à ', 'de ', 'en ', 'vers ', 'près de ',
    'né à', 'née à', 'domicilié à',
    # German
    'in ', 'nach ', 'aus ', 'bei ',
]


def detect_places(text: str) -> List[Match]:
    """
    Detect place names (cities, towns) in text.

    Uses a combination of:
    1. Known place names from a static list
    2. Context-based detection for unknown places
    """
    matches = []
    seen_positions: Set[tuple] = set()
    text_lower = text.lower()

    # Method 1: Match known places
    for place in KNOWN_PLACES:
        # Case-insensitive search for the place name
        pattern = r'\b' + re.escape(place) + r'\b'
        for m in re.finditer(pattern, text, re.IGNORECASE):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                seen_positions.add(pos)
                matches.append(Match(
                    text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    category='PLACE',
                    confidence=0.95,
                    context=text[max(0, m.start()-20):m.end()+20]
                ))

    # Method 2: Context-based detection for unknown places
    # Pattern: context word + capitalized word (likely a place)
    context_pattern = r'(?:te|in|naar|uit|van|bij)\s+([A-Z][a-zé-]+(?:-[A-Z][a-zé]+)?)\b'
    for m in re.finditer(context_pattern, text):
        place_name = m.group(1)
        pos = (m.start(1), m.end(1))

        if pos not in seen_positions:
            # Skip if it's a common word that looks like a place
            if place_name.lower() in {'het', 'de', 'een', 'dit', 'dat', 'deze'}:
                continue
            # Skip if already in known places (already matched above)
            if place_name in KNOWN_PLACES:
                continue
            # Skip very short words
            if len(place_name) < 3:
                continue

            seen_positions.add(pos)
            matches.append(Match(
                text=place_name,
                start=m.start(1),
                end=m.end(1),
                category='PLACE',
                confidence=0.75,  # Lower confidence for context-based
                context=text[max(0, m.start()-20):m.end(1)+20]
            ))

    return matches


# =============================================================================
# STREET NAME PATTERNS (Standalone streets without house numbers)
# =============================================================================

# Dutch/Belgian street suffixes
STREET_SUFFIXES = [
    'straat', 'laan', 'weg', 'plein', 'singel', 'dreef', 'lei', 'steenweg',
    'kaai', 'baan', 'dijk', 'gracht', 'kade', 'pad', 'hof', 'park',
    'boulevard', 'avenue', 'ring', 'passage', 'galerij', 'markt',
]

# Pattern for standalone street names (without house numbers)
# This catches streets mentioned without addresses, like "op de Grote Markt"
STREET_PATTERNS = [
    # Dutch/Belgian: Stationstraat, Grote Markt, Sint-Jacobsstraat
    r'\b(?:de\s+)?(?:Grote|Kleine|Oude|Nieuwe|Sint|St\.|Heilige|Lange|Korte)?\s*[A-Z][a-zé]+(?:straat|laan|weg|plein|singel|dreef|lei|steenweg|kaai|baan|dijk|gracht|kade|pad|hof|park|boulevard|avenue|ring|markt)\b',

    # Compound street names: Van Eyckstraat, Koning Albertlaan
    r'\b(?:Van|De|Het|Den|Ter)\s+[A-Z][a-zé]+(?:straat|laan|weg|plein)\b',

    # Named streets: Koningin Astridlaan, President Kennedylaan
    r'\b(?:Koning|Koningin|President|Generaal|Kolonel|Burgemeester|Professor|Dokter|Prins|Prinses)\s+[A-Z][a-zé]+(?:straat|laan|weg|plein)\b',
]

# Context words before standalone street mentions
STREET_CONTEXT = [
    'op de ', 'in de ', 'aan de ', 'naar de ', 'via de ', 'langs de ',
    'nabij de ', 'ter hoogte van de ', 'aan het ', 'op het ',
]


def detect_streets(text: str) -> List[Match]:
    """
    Detect standalone street names (without house numbers).

    Street names WITH house numbers are already captured as ADDRESS.
    This detector finds mentions like "op de Grote Markt" or "via de Stationstraat".
    """
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern in STREET_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            street_name = m.group()

            if pos not in seen_positions:
                # Skip if followed by a house number (that's an ADDRESS)
                after_match = text[m.end():m.end()+10]
                if re.match(r'\s*\d+', after_match):
                    continue

                # Skip if contains newlines
                if '\n' in street_name:
                    continue

                # Skip very short matches
                if len(street_name) < 5:
                    continue

                seen_positions.add(pos)
                matches.append(Match(
                    text=street_name,
                    start=m.start(),
                    end=m.end(),
                    category='STREET',
                    confidence=0.85,
                    context=text[max(0, m.start()-20):m.end()+20]
                ))

    return matches


# =============================================================================
# PERSON NAME PATTERNS
# =============================================================================

# Common name particles (all languages)
NAME_PARTICLES = {
    # Dutch/Belgian
    'van', 'de', 'der', 'den', 'el', 'al', 'ten', 'ter', 'la', 'le',
    # French
    'du', 'des', 'le', 'la', 'les',
    # German
    'von', 'zu', 'vom', 'zum', 'zur',
    # Spanish/Portuguese
    'da', 'do', 'dos', 'das',
    # Irish/Scottish
    "o'", 'mc', 'mac',
}

# Pattern for names in various formats
NAME_PATTERNS = [
    # === DUTCH/BELGIAN ===
    # Full name with particle (caps): EL MANSOURI Brahim, VAN LOOVEREN Thomas
    r'\b(?:EL|VAN|DE|DER|DEN|TEN|TER)\s+[A-Z]{2,}\s+[A-Z][a-zé]+(?:\s+[A-Z][a-zé]+)?\b',
    # Full name with particle (mixed): El Mansouri Brahim, Van Looveren Thomas
    r'\b(?:El|Van|De|Der|Den|Ten|Ter|La|Le)\s+[A-Z][a-zé]+\s+[A-Z][a-zé]+(?:\s+[A-Z][a-zé]+)?\b',

    # === FRENCH ===
    # Jean-Pierre Dupont, Marie-Claire de la Fontaine
    r'\b(?:Jean|Marie|Pierre|Jacques|Philippe|François|Michel|André|Louis|Charles)[-\s][A-Z][a-zé]+(?:\s+(?:de|du|la|le)\s+[A-Z][a-zé]+)?\b',
    # de la Fontaine, du Pont
    r'\b(?:de|du)\s+(?:la\s+)?[A-Z][a-zé]+\s+[A-Z][a-zé]+\b',

    # === GERMAN ===
    # von Braun, von der Leyen
    r'\b(?:von|zu|vom)\s+(?:der\s+)?[A-Z][a-zé]+(?:\s+[A-Z][a-zé]+)?\b',

    # === IRISH/SCOTTISH ===
    # O'Brien, O'Connor, McDonald, MacArthur
    r"\bO'[A-Z][a-z]+\b",
    r'\b(?:Mc|Mac)[A-Z][a-z]+\b',

    # === UNIVERSAL PATTERNS ===
    # LASTNAME Firstname Middlename: GOURMA Jonathan Aya, DETOLLENAERE Renaat, SMITH John
    r'\b[A-Z]{2,}(?:\s+[A-Z][a-zé]+){1,3}\b',

    # Firstname LASTNAME: Renaat DETOLLENAERE, John SMITH
    r'\b[A-Z][a-zé]+\s+[A-Z]{2,}\b',

    # All caps with particle only (Dutch): EL MANSOURI
    # But NOT followed by common legal terms
    r'\b(?:EL|VAN|DE)\s+(?!ERSTE|EERSTE|AANLEG|VLAANDEREN|NEDERLAND|FRANCE|GERMANY)[A-Z]{2,}\b',

    # === TITLE + NAME (context-based) ===
    # Mr. John Smith, Mrs. Jane Doe, Dr. Smith
    r'\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b',
]

# Common false positives to exclude (legal terms and places that look like names)
NAME_EXCLUSIONS = {
    # Legal terms
    'VAN EERSTE', 'DE EERSTE', 'VAN AANLEG', 'DE AANLEG',
    'VLAANDEREN', 'NEDERLAND', 'BELGIE', 'BELGIUM',
    'PRO JUSTITIA', 'EUR', 'SEPA', 'BTW', 'BIC',
    # Street/place names that match name patterns
    'DE GROTE MARKT', 'DE KLEINE MARKT', 'DE OUDE MARKT',
    'DE GROTE PLAATS', 'HET GROTE PLEIN', 'DE MARKT',
    'VAN DE MARKT', 'VAN HET PLEIN',
}

# Words that indicate this is a place, not a person (check end of match)
PLACE_SUFFIX_EXCLUSIONS = {
    'markt', 'plein', 'straat', 'laan', 'weg', 'dreef', 'lei',
    'kaai', 'dijk', 'gracht', 'park', 'bos', 'hof', 'tuin',
    'kerk', 'station', 'haven', 'poort', 'brug', 'centrum',
}

# Context words that indicate a name follows - multi-language
NAME_CONTEXT_BEFORE = [
    # Dutch/Belgian
    'genaamd', 'verdachte', 'naam:', 'voornaam:',
    'abonnee', 'geregistreerd op', 'in gebruik door',
    'vader van', 'moeder van', 'broer van', 'zus van',
    'echtgenoot van', 'echtgenote van',
    # English
    'name:', 'named', 'called', 'suspect', 'defendant',
    'father of', 'mother of', 'brother of', 'sister of',
    'husband of', 'wife of', 'spouse of',
    'from:', 'by:', 'contact:',
    # French
    'nommé', 'appelé', 'suspect', 'prévenu',
    'père de', 'mère de', 'frère de', 'sœur de',
    'époux de', 'épouse de',
    # German
    'namens', 'genannt', 'verdächtige', 'angeklagter',
    'vater von', 'mutter von', 'bruder von', 'schwester von',
]


def detect_names(text: str) -> List[Match]:
    """
    Detect person names in text.

    This is the trickiest detector - names appear in many formats.
    We use patterns + context to find them.
    """
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern in NAME_PATTERNS:
        for m in re.finditer(pattern, text):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                name = m.group()

                # Skip if it's a common word/acronym/legal term (false positive)
                name_upper = name.upper()
                if name_upper in NAME_EXCLUSIONS:
                    continue

                # Skip if contains location/region names
                if any(loc in name_upper for loc in ['VLAANDEREN', 'NEDERLAND', 'BELGIE', 'AFDELING']):
                    continue

                # Skip if ends with a place suffix (e.g., "de Grote Markt" is a place, not a person)
                name_lower = name.lower()
                last_word = name_lower.split()[-1] if name_lower.split() else ''
                if last_word in PLACE_SUFFIX_EXCLUSIONS:
                    continue

                # Skip if it contains newlines (spans multiple logical lines)
                if '\n' in name:
                    continue

                # Skip very short matches
                if len(name) < 5:
                    continue

                seen_positions.add(pos)
                matches.append(Match(
                    text=name,
                    start=m.start(),
                    end=m.end(),
                    category='PERSON',
                    confidence=0.80,
                    context=text[max(0, m.start()-30):m.end()+20]
                ))

    return matches


# =============================================================================
# CONTEXT-BASED NAME DETECTION (for names spaCy misses)
# =============================================================================

def detect_names_by_context(text: str) -> List[Match]:
    """
    Detect person names based on document context patterns.

    This catches names that spaCy misses (non-Western names, unusual formats).

    Patterns detected:
    - "FIRSTNAME LASTNAME - DD-MM-YYYY" (name before birthdate)
    - "NAME - Nationaliteit:"
    - Names in ALLCAPS followed by names in Mixed case
    """
    matches = []
    seen_positions: Set[tuple] = set()

    # Pattern 1: Name before birth date (DD-MM-YYYY or DD/MM/YYYY)
    # Catches: "OPO KUAA Daniel Kwame - 27-01-2001"
    # Catches: "Dikila-Djokoto D'Arcki - 24-10-2000"
    name_before_date = r"([A-Z][A-Za-zé\'\-]+(?:\s+[A-Z]?[a-zé\'\-]+)*(?:\s+[A-Z][A-Za-zé\'\-]+)*)\s*[-–]\s*\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4}"

    for m in re.finditer(name_before_date, text):
        name = m.group(1).strip()
        pos = (m.start(), m.start() + len(name))

        # Skip if too short or looks like a placeholder
        if len(name) < 3 or '_' in name:
            continue

        # Skip common non-name words
        if name.lower() in {'geboren', 'geboortedatum', 'datum', 'nationaliteit', 'wettelijke', 'werkelijke'}:
            continue

        if pos not in seen_positions:
            seen_positions.add(pos)
            matches.append(Match(
                text=name,
                start=pos[0],
                end=pos[1],
                category='PERSON',
                confidence=0.88,
                context=text[max(0, pos[0]-10):pos[1]+30]
            ))

    # Pattern 2: ALLCAPS name (likely surname) followed by optional given names
    # Catches: "THOMPSON", "SEEDORF", "ARKO"
    # But only when it looks like a name context (followed by date, nationality, etc.)
    allcaps_name = r'\b([A-Z]{3,}(?:\s+[A-Z][a-z]+)*)\s*(?:[-–]\s*\d{1,2}[-/\.]|Nationaliteit|PERSON_|geboren)'

    for m in re.finditer(allcaps_name, text):
        name = m.group(1).strip()
        pos = (m.start(), m.start() + len(name))

        # Skip placeholders and common words
        if '_' in name or name in {'PERSON', 'PLACE', 'STREET', 'PHONE', 'EMAIL', 'VEHICLE', 'ROAD', 'PAGE'}:
            continue

        # Skip if already captured
        if any(not (pos[1] <= s or pos[0] >= e) for s, e in seen_positions):
            continue

        if pos not in seen_positions:
            seen_positions.add(pos)
            matches.append(Match(
                text=name,
                start=pos[0],
                end=pos[1],
                category='PERSON',
                confidence=0.85,
                context=text[max(0, pos[0]-10):pos[1]+30]
            ))

    # Pattern 3: Names after partially replaced text
    # Catches remaining parts like "Salu Kia Zola" before "PERSON_1062"
    partial_name = r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s+PERSON_\d{3,4}'

    for m in re.finditer(partial_name, text):
        name = m.group(1).strip()
        pos = (m.start(), m.start() + len(name))

        if len(name) < 4:
            continue

        if pos not in seen_positions:
            seen_positions.add(pos)
            matches.append(Match(
                text=name,
                start=pos[0],
                end=pos[1],
                category='PERSON',
                confidence=0.82,
                context=text[max(0, pos[0]-10):pos[1]+30]
            ))

    return matches


# =============================================================================
# VEHICLE DETECTION (Car brands and models)
# =============================================================================

# Common car brands (European, Asian, American)
VEHICLE_BRANDS = {
    # European
    'fiat', 'bmw', 'mercedes', 'mercedes-benz', 'audi', 'volkswagen', 'vw',
    'opel', 'peugeot', 'renault', 'citroën', 'citroen', 'volvo', 'skoda',
    'seat', 'porsche', 'ferrari', 'lamborghini', 'alfa', 'mini', 'smart',
    'jaguar', 'land rover', 'landrover', 'bentley', 'rolls-royce', 'aston martin',
    'maserati', 'bugatti', 'dacia', 'lancia', 'saab',
    # Asian
    'toyota', 'honda', 'nissan', 'mazda', 'hyundai', 'kia', 'suzuki',
    'mitsubishi', 'lexus', 'subaru', 'isuzu', 'daihatsu', 'infiniti',
    'acura', 'genesis', 'ssangyong',
    # American
    'ford', 'chevrolet', 'chevy', 'dodge', 'jeep', 'tesla', 'cadillac',
    'chrysler', 'buick', 'gmc', 'lincoln', 'ram', 'hummer',
    # Commercial vehicles
    'iveco', 'man', 'daf', 'scania', 'renault trucks',
}

# Common van/truck models (often used in investigations)
VEHICLE_MODELS = {
    'ducato', 'sprinter', 'transit', 'transporter', 'crafter', 'vivaro',
    'trafic', 'master', 'boxer', 'jumper', 'daily', 'vito', 'caddy',
    'berlingo', 'partner', 'kangoo', 'combo', 'doblo', 'nv200', 'hiace',
    'golf', 'polo', 'passat', 'corsa', 'astra', 'focus', 'fiesta',
    'civic', 'corolla', 'camry', 'yaris', 'clio', 'megane', 'scenic',
    '3-serie', '5-serie', 'a3', 'a4', 'a6', 'c-klasse', 'e-klasse',
}


def detect_vehicles(text: str) -> List[Match]:
    """
    Detect vehicle brands and models.

    Catches:
    - Brand only: "een BMW", "de Mercedes"
    - Brand + model: "Fiat Ducato", "Mercedes Sprinter"
    - Model only (common vans): "de Ducato", "een Sprinter"
    """
    matches = []
    seen_positions: Set[tuple] = set()

    # Pattern for brand + optional model
    # Catches: "Fiat Ducato", "BMW X5", "Mercedes-Benz Sprinter"
    for brand in VEHICLE_BRANDS:
        # Escape special chars and make case-insensitive
        brand_pattern = re.escape(brand)
        # Match brand optionally followed by model/type
        pattern = rf'\b({brand_pattern}(?:\s+[A-Za-z0-9\-]+)?)\b'

        for m in re.finditer(pattern, text, re.IGNORECASE):
            vehicle = m.group(1)
            pos = (m.start(), m.end())

            # Skip very short matches (avoid "VW" alone matching random text)
            if len(vehicle) < 3:
                continue

            if pos not in seen_positions:
                seen_positions.add(pos)
                matches.append(Match(
                    text=vehicle,
                    start=m.start(),
                    end=m.end(),
                    category='VEHICLE',
                    confidence=0.92,
                    context=text[max(0, m.start()-20):m.end()+20]
                ))

    # Also detect standalone common models (Ducato, Sprinter, Transit)
    for model in VEHICLE_MODELS:
        pattern = rf'\b({re.escape(model)})\b'
        for m in re.finditer(pattern, text, re.IGNORECASE):
            pos = (m.start(), m.end())
            if pos not in seen_positions:
                # Check it's not already part of a brand match
                overlaps = any(
                    not (pos[1] <= s or pos[0] >= e)
                    for s, e in seen_positions
                )
                if not overlaps:
                    seen_positions.add(pos)
                    matches.append(Match(
                        text=m.group(1),
                        start=m.start(),
                        end=m.end(),
                        category='VEHICLE',
                        confidence=0.88,
                        context=text[max(0, m.start()-20):m.end()+20]
                    ))

    return matches


# =============================================================================
# ROAD/HIGHWAY DETECTION (Context-aware)
# =============================================================================

def detect_roads(text: str) -> List[Match]:
    """
    Detect road/highway numbers.

    Catches Belgian/Dutch/European road numbering:
    - N-roads: N133, N16, n302 (national roads)
    - A-roads: A12, A1, a28 (autosnelwegen/motorways)
    - E-roads: E40, E19 (European routes)
    - R-roads: R1, R0 (ring roads)
    """
    matches = []
    seen_positions: Set[tuple] = set()

    # Road number pattern - very reliable structural pattern
    # Matches: N133, A12, E19, R1, n302, a1 (case insensitive)
    pattern = r'\b[NAERnaer]\d{1,4}\b'

    for m in re.finditer(pattern, text):
        pos = (m.start(), m.end())
        if pos not in seen_positions:
            seen_positions.add(pos)
            matches.append(Match(
                text=m.group(),
                start=m.start(),
                end=m.end(),
                category='ROAD',
                confidence=0.95,
                context=text[max(0, m.start()-20):m.end()+20]
            ))

    return matches


# =============================================================================
# CONTEXT-BASED LOCATION DETECTION (Foolproof approach)
# =============================================================================

# Dutch/Belgian location context markers
LOCATION_MARKERS = [
    # "te [PLACE]" - most reliable Dutch location marker
    (r'\bte\s+([A-Z][a-zA-Zé\-]+(?:\s*-\s*[A-Z][a-zA-Zé]+)?)', 'te'),
    # "richting [PLACE]" - direction indicator
    (r'\brichting\s+([A-Z][a-zA-Zé\-]+)', 'richting'),
    # "naar [PLACE]" - destination
    (r'\bnaar\s+([A-Z][a-zA-Zé\-]+)', 'naar'),
    # "vanuit [PLACE]" - origin
    (r'\bvanuit\s+([A-Z][a-zA-Zé\-]+)', 'vanuit'),
    # "via [PLACE]" - via
    (r'\bvia\s+([A-Z][a-zA-Zé\-]+)', 'via'),
    # "t.h.v. [PLACE]" or "ter hoogte van [PLACE]"
    (r'\bt\.?h\.?v\.?\s+([A-Z][a-zA-Zé\-]+)', 'thv'),
    (r'\bter hoogte van\s+([A-Z][a-zA-Zé\-]+)', 'thv'),
    # Belgian postal code + place: "2990 Wuustwezel", "9000 Gent"
    (r'\b\d{4}\s+([A-Z][a-zA-Zé\-]+)\b', 'postalcode_be'),
    # Dutch postal code + place: "1234 AB Amsterdam"
    (r'\b\d{4}\s*[A-Z]{2}\s+([A-Z][a-zA-Zé\-]+)\b', 'postalcode_nl'),
    # Reverse: place + postal code (common in cell tower data): "WUUSTWEZEL 2990"
    (r'\b([A-Z]{3,})\s+\d{4}\b', 'place_postalcode'),
    # "richting [place]" case-insensitive: "richting breda", "richting ANTWERPEN"
    (r'\brichting\s+([a-zA-Z][a-zA-Zé\-]+)', 'richting_ci'),
]

# Words that look like places but aren't (Dutch common words)
PLACE_EXCLUSIONS = {
    'het', 'de', 'een', 'van', 'naar', 'met', 'voor', 'door', 'over',
    'België', 'Nederland', 'Duitsland', 'Frankrijk',  # Countries (usually OK to keep)
    'Politie', 'Justitie', 'Parket', 'Rechtbank',  # Institutions
    'Procureur', 'Onderzoeksrechter', 'Commissaris',
    'Maandag', 'Dinsdag', 'Woensdag', 'Donderdag', 'Vrijdag', 'Zaterdag', 'Zondag',
    'Januari', 'Februari', 'Maart', 'April', 'Mei', 'Juni',
    'Juli', 'Augustus', 'September', 'Oktober', 'November', 'December',
}


def detect_context_places(text: str) -> List[Match]:
    """
    Detect places based on context markers (foolproof approach).

    This catches places that spaCy misses by looking for Dutch location patterns:
    - "te Wuustwezel" → Wuustwezel is a place
    - "richting Antwerpen" → Antwerpen is a place
    - "naar Brussel" → Brussel is a place
    """
    matches = []
    seen_positions: Set[tuple] = set()

    for pattern, marker_type in LOCATION_MARKERS:
        for m in re.finditer(pattern, text):
            place_name = m.group(1)

            # Skip exclusions
            if place_name in PLACE_EXCLUSIONS:
                continue

            # Skip if too short
            if len(place_name) < 3:
                continue

            # Calculate position of the place name (not the marker)
            place_start = m.start() + m.group(0).index(place_name)
            place_end = place_start + len(place_name)
            pos = (place_start, place_end)

            if pos not in seen_positions:
                seen_positions.add(pos)
                matches.append(Match(
                    text=place_name,
                    start=place_start,
                    end=place_end,
                    category='PLACE',
                    confidence=0.90,
                    context=text[max(0, m.start()-10):m.end()+10]
                ))

    return matches


def detect_any_street(text: str) -> List[Match]:
    """
    Aggressively detect ANY word ending in Dutch street suffixes.

    This is more foolproof than specific patterns - catches:
    - Kampweg, Noorderlaan, Stationstraat, etc.
    - Even unknown/new streets
    """
    matches = []
    seen_positions: Set[tuple] = set()

    # All common Dutch/Belgian street suffixes
    suffixes = (
        'straat', 'laan', 'weg', 'plein', 'singel', 'dreef', 'lei', 'steenweg',
        'kaai', 'baan', 'dijk', 'gracht', 'kade', 'pad', 'hof', 'park',
        'boulevard', 'avenue', 'ring', 'passage', 'markt', 'poort', 'dam',
        'vest', 'wal', 'statie', 'square', 'plaats', 'berg', 'brug',
    )

    # Dutch words that end in street suffixes but AREN'T streets
    # This prevents false positives from aggressive suffix matching
    NOT_STREETS = {
        # -ring words (not Ring roads)
        'overlevering', 'uitvoering', 'niet-uitvoering', 'levering', 'bezorging',
        'herinnering', 'verandering', 'verbetering', 'verklaring', 'bewering',
        'ervaring', 'oefening', 'vergadering', 'bediening', 'besturing',
        'verwijdering', 'verschijning', 'verbinding', 'beëindiging', 'opening',
        'sluiting', 'aflevering', 'inlevering', 'aanlevering', 'toelevering',
        # -weg words (not roads)
        'onderweg', 'halverwege', 'vanwege', 'wegens',
        # -laan words
        'verlaan',
        # -dam words
        'schadedam', 'verdamdam',
        # -plein words
        'volplein',
        # -baan words
        'loopbaan', 'rijbaan', 'racebaan', 'vliegbaan', 'schaatsbaan',
        'wielerbaan', 'omloopbaan', 'glijbaan',
        # -pad words
        'tegenpad', 'voetpad', 'fietspad', 'wandelpad', 'bospad',
        # -berg words
        'ijsberg', 'zandberg', 'afvalberg', 'schuldenberg',
        # -poort words
        'paspoort', 'exportpoort', 'importpoort',
        # -brug words
        'luchtbrug', 'touwbrug',
        # -vest words
        'zwemvest', 'reddingsvest', 'kogelvrijevest',
        # -markt words
        'arbeidsmarkt', 'huizenmarkt', 'woningmarkt', 'aandelenmarkt', 'obligatiemarkt',
        # other
        'rechtbank', 'vooruitgang', 'achteruitgang',
    }

    # Pattern: any word (including compound) ending in a street suffix
    # Catches: Kampweg, Sint-Jacobsstraat, Koningin Astridlaan, etc.
    pattern = r'\b[A-Za-zé\-]+(?:' + '|'.join(suffixes) + r')\b'

    for m in re.finditer(pattern, text, re.IGNORECASE):
        street_name = m.group()
        pos = (m.start(), m.end())

        # Skip very short matches
        if len(street_name) < 6:
            continue

        # Skip if it's just the suffix alone
        suffix_only = any(street_name.lower() == s for s in suffixes)
        if suffix_only:
            continue

        # Skip known non-street words
        if street_name.lower() in NOT_STREETS:
            continue

        # Skip words ending in common non-street patterns
        lower = street_name.lower()
        if lower.endswith('ering') or lower.endswith('ing') and not lower.endswith('ring'):
            # Most -ing words aren't streets (vergadering, bediening, etc.)
            # But real -ring streets exist (Antwerpse Ring)
            # Only skip -ering words which are almost never streets
            if lower.endswith('ering'):
                continue

        if pos not in seen_positions:
            seen_positions.add(pos)
            matches.append(Match(
                text=street_name,
                start=m.start(),
                end=m.end(),
                category='STREET',
                confidence=0.88,
                context=text[max(0, m.start()-20):m.end()+20]
            ))

    return matches


# =============================================================================
# COMBINED DETECTION
# =============================================================================

def detect_all(text: str) -> List[Match]:
    """
    Run all detectors and return combined results.

    Results are sorted by position (start) for proper replacement.
    """
    all_matches = []

    # Run each detector (order matters - higher confidence first)
    all_matches.extend(detect_emails(text))           # Highest confidence
    all_matches.extend(detect_ibans(text))            # High confidence
    all_matches.extend(detect_phones(text))           # High confidence
    all_matches.extend(detect_vehicles(text))         # Car brands/models
    all_matches.extend(detect_roads(text))            # Road numbers (N133, A12)
    all_matches.extend(detect_dates_of_birth(text))
    all_matches.extend(detect_addresses(text))        # Full addresses first
    all_matches.extend(detect_any_street(text))       # Aggressive street detection
    all_matches.extend(detect_context_places(text))   # Context-based places ("te X")
    all_matches.extend(detect_places(text))           # Known city/town names
    all_matches.extend(detect_national_ids(text))
    all_matches.extend(detect_names_by_context(text)) # Names before dates, ALLCAPS names
    all_matches.extend(detect_names(text))            # Regex name patterns (run last)

    # Remove overlapping matches (keep higher confidence)
    all_matches = _remove_overlaps(all_matches)

    # Sort by position
    all_matches.sort(key=lambda m: m.start)

    return all_matches


def _remove_overlaps(matches: List[Match]) -> List[Match]:
    """Remove overlapping matches, keeping higher confidence ones."""
    if not matches:
        return []

    # Sort by confidence (descending) then by length (descending)
    matches.sort(key=lambda m: (-m.confidence, -(m.end - m.start)))

    kept = []
    used_ranges = []

    for match in matches:
        # Check if this overlaps with any kept match
        overlaps = False
        for start, end in used_ranges:
            if not (match.end <= start or match.start >= end):
                overlaps = True
                break

        if not overlaps:
            kept.append(match)
            used_ranges.append((match.start, match.end))

    return kept
