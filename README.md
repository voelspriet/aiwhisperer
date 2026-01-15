# DocSanitizer

Strip sensitive data from documents for safe AI analysis. Replace names, phone numbers, addresses, vehicles, and more with placeholders while preserving document structure. Decode AI output back to original values.

**Supports 6 languages:** Dutch, English, German, French, Italian, Spanish

Based on the workflow described by Henk van Ess in ["Speed reading a massive criminal investigation"](https://digitaldigging.org).

## The Concept

```
ORIGINAL:  "Jan de Vries reed met zijn Fiat Ducato naar Antwerpen via de N133"
                    ↓ encode
SANITIZED: "PERSON_001 reed met zijn VEHICLE_001 naar PLACE_001 via de ROAD_001"
                    ↓ send to AI for analysis
AI OUTPUT: "PERSON_001 used VEHICLE_001 to travel to PLACE_001 via ROAD_001..."
                    ↓ decode
DECODED:   "Jan de Vries used Fiat Ducato to travel to Antwerpen via N133..."
```

**What changes:** Sensitive values (names, locations, phones, emails, IBANs, vehicles, roads, etc.)
**What stays:** Structure, relationships, context, amounts, dates

## Why Use This?

- **Privacy-safe AI analysis** - Send documents to AI without exposing personal data
- **Consistent placeholders** - Same person/place always gets the same placeholder
- **Round-trip safe** - Decode AI output back to real names exactly
- **Multi-language** - Native NER support for 6 European languages
- **Large file support** - Handles documents of any size with automatic chunking
- **Offline** - All processing happens locally

## Installation

```bash
# Basic install (pattern-based detection only)
pip install docsanitizer

# Recommended: with spaCy for NER-based name/location detection
pip install docsanitizer[spacy]

# Then download language models you need:
python -m spacy download nl_core_news_sm  # Dutch
python -m spacy download en_core_web_sm   # English
python -m spacy download de_core_news_sm  # German
python -m spacy download fr_core_news_sm  # French
python -m spacy download it_core_news_sm  # Italian
python -m spacy download es_core_news_sm  # Spanish
```

For development:
```bash
git clone https://github.com/voelspriet/docsanitizer
cd docsanitizer
pip install -e ".[spacy,dev]"
```

## Quick Start

### Command Line

```bash
# Encode a document (uses hybrid detection by default)
docsanitizer encode document.txt

# Outputs:
#   document_sanitized.txt  - Safe to send to AI
#   document_mapping.json   - Keep locally for decoding

# Include legend header (recommended for AI analysis)
docsanitizer encode document.txt --legend

# Specify language (default: nl)
docsanitizer encode document.txt -l en

# Use different anonymization strategy
docsanitizer encode document.txt --strategy mask

# After AI analysis, decode the output
docsanitizer decode ai_output.txt -m document_mapping.json

# Preview what would be detected (dry run)
docsanitizer encode document.txt --dry-run

# Analyze detection statistics
docsanitizer analyze document.txt
```

### Python API

```python
from docsanitizer import encode, decode, Mapping

# Encode with hybrid detection (spaCy NER + patterns)
text = "Jan de Vries reed met zijn BMW X5 naar Antwerpen via de A12"
sanitized, mapping = encode(text, language='nl')
print(sanitized)
# "PERSON_001 reed met zijn VEHICLE_001 naar PLACE_001 via de ROAD_001"

# Save mapping for later
mapping.save("mapping.json")

# ... send sanitized text to AI ...

# Decode AI output
ai_output = "PERSON_001 was seen near PLACE_001 at 15:30"
decoded = decode(ai_output, mapping)
print(decoded)
# "Jan de Vries was seen near Antwerpen at 15:30"
```

### With Legend (Recommended for AI)

```python
from docsanitizer import encode_with_legend

text = "..."  # Your document
sanitized, mapping = encode_with_legend(text, language='nl')

# sanitized now includes a header explaining all placeholder categories
# This helps AI understand the document structure
```

The legend looks like:
```
============================================================
DOCUMENT LEGEND - PLACEHOLDER KEY
============================================================

This document has been sanitized. Sensitive data has been
replaced with placeholders. Each placeholder follows the
format CATEGORY_NNN (e.g., PERSON_001, PLACE_002).

PLACEHOLDER CATEGORIES:

  PERSON_NNN : Person names (individuals) (15 unique)
  PLACE_NNN : Locations (cities, towns, regions) (8 unique)
  VEHICLE_NNN : Vehicle brands and models (cars, vans, trucks) (3 unique)
  ROAD_NNN : Road/highway numbers (N-roads, A-roads, E-roads) (4 unique)
  PHONE_NNN : Phone numbers (12 unique)

IMPORTANT: Different numbers = different entities.
  PERSON_001 and PERSON_002 are two different people.
  PLACE_001 appearing twice means the SAME location.

============================================================
```

## What Gets Detected

### Via spaCy NER (names & locations)

| Category | Examples | Languages |
|----------|----------|-----------|
| **PERSON** | `Jan de Vries`, `El Mansouri Brahim`, `Marie Dupont` | All 6 |
| **PLACE** | `Amsterdam`, `Antwerpen`, `Brussels`, `Berlin` | All 6 |
| **ORG** | `Rabobank`, `Microsoft` (optional) | All 6 |

### Via Pattern Matching (structured data)

| Category | Examples | Confidence |
|----------|----------|------------|
| **EMAIL** | `jan@example.com`, `info@company.be` | 99% |
| **PHONE** | `+32 489 66 70 88`, `052/26.08.60`, `(555) 123-4567` | 95% |
| **IBAN** | `BE44 3770 8065 6345`, `NL91 ABNA 0417 1643 00` | 95% |
| **VEHICLE** | `Fiat Ducato`, `BMW X5`, `Mercedes Sprinter`, `Toyota Corolla` | 92% |
| **ROAD** | `N133`, `A12`, `E19`, `R1` (Belgian/Dutch/European roads) | 95% |
| **STREET** | `Stationstraat`, `Koning Albertlaan`, `Grote Markt` | 88% |
| **DOB** | `26/04/1993` (with birth context) | 90% |
| **ID** | `123456782` (Dutch BSN with 11-proef), Belgian Rijksregisternummer | 85% |

### Via Context Detection (foolproof approach)

DocSanitizer uses context markers to catch locations that spaCy might miss:

| Pattern | Example | Detection |
|---------|---------|-----------|
| `te [PLACE]` | `te Wuustwezel` | Wuustwezel → PLACE |
| `richting [PLACE]` | `richting Antwerpen` | Antwerpen → PLACE |
| `naar [PLACE]` | `naar Brussel` | Brussel → PLACE |
| `[POSTALCODE] [PLACE]` | `2990 Wuustwezel` | Wuustwezel → PLACE |
| `[NAME] - [DATE]` | `Thompson - 15-03-1985` | Thompson → PERSON |

## Supported Vehicle Brands

European: Fiat, BMW, Mercedes, Audi, Volkswagen, Opel, Peugeot, Renault, Citroën, Volvo, Porsche, Ferrari, etc.

Asian: Toyota, Honda, Nissan, Mazda, Hyundai, Kia, Mitsubishi, Lexus, etc.

American: Ford, Chevrolet, Tesla, Jeep, Dodge, Cadillac, etc.

Commercial: Iveco, MAN, DAF, Scania, plus models like Ducato, Sprinter, Transit, Transporter, etc.

## Detection Backends

DocSanitizer uses a **hybrid approach** by default, combining the best of both methods:

| Backend | What it detects | Pros | Cons |
|---------|-----------------|------|------|
| **hybrid** (default) | Names, locations via NER + structured data via patterns | Best accuracy, context-aware | Requires spaCy |
| **patterns** | Structured data + context-based detection | Fast, no dependencies | May miss some names |
| **spacy** | NER entities only | Good for names | Misses structured data |

```python
# Hybrid (recommended) - requires spaCy
sanitized, mapping = encode(text, backend='hybrid', language='nl')

# Patterns only - no dependencies needed
sanitized, mapping = encode(text, backend='patterns')
```

## Anonymization Strategies

| Strategy | Example | Use case |
|----------|---------|----------|
| **replace** (default) | `jan@example.com` → `EMAIL_001` | Reversible, for AI analysis |
| **redact** | `jan@example.com` → `[EMAIL]` | Non-reversible, generic |
| **mask** | `jan@example.com` → `j**@e******.com` | Partial visibility |
| **hash** | `jan@example.com` → `a1b2c3d4` | One-way, consistent |

```python
# Default: reversible placeholders
sanitized, _ = encode(text, strategy='replace')

# Mask sensitive data partially
sanitized, _ = encode(text, strategy='mask')
```

## Supported Languages

| Code | Language | spaCy Model |
|------|----------|-------------|
| `nl` | Dutch | `nl_core_news_sm` |
| `en` | English | `en_core_web_sm` |
| `de` | German | `de_core_news_sm` |
| `fr` | French | `fr_core_news_sm` |
| `it` | Italian | `it_core_news_sm` |
| `es` | Spanish | `es_core_news_sm` |

```bash
# Dutch (default)
docsanitizer encode document.txt -l nl

# English
docsanitizer encode document.txt -l en

# German
docsanitizer encode document.txt -l de
```

## Advanced Usage

### Large File Support

DocSanitizer automatically handles large files by processing them in chunks:

```python
# Files larger than 500KB are automatically chunked
# This happens transparently - just use the normal API
sanitized, mapping = encode(large_document, language='nl')
```

### Batch Processing

```python
from docsanitizer import encode, Mapping

# Reuse mapping across documents for consistent placeholders
mapping = Mapping()

for doc in documents:
    sanitized, mapping = encode(doc, mapping=mapping)
    process(sanitized)

# Save once at the end
mapping.save("batch_mapping.json")
```

### Include Organizations

```python
from docsanitizer.detectors import detect_hybrid

# By default, organizations are not anonymized
# Enable with include_org=True
matches = detect_hybrid(text, include_org=True)
```

### Statistics

```python
from docsanitizer import encode, get_statistics

sanitized, mapping = encode(text)
stats = get_statistics(mapping)
print(f"Found {stats['total_unique_values']} unique sensitive values")
print(f"Categories: {list(stats['by_category'].keys())}")
```

## Workflow Example: Criminal Investigation Analysis

```bash
# 1. Sanitize the investigation file
docsanitizer encode investigation.txt --legend

# 2. Send investigation_sanitized.txt to AI for analysis
#    Ask AI to identify relationships, timelines, patterns

# 3. Save AI output as analysis_result.txt

# 4. Decode AI output back to real names
docsanitizer decode analysis_result.txt -m investigation_mapping.json

# Now you have the AI's analysis with real names restored
```

## Features Summary

- **Multi-language**: 6 languages with native NER models
- **Hybrid detection**: spaCy NER + patterns + context-based detection
- **Vehicle detection**: 50+ car brands and common models
- **Road detection**: N/A/E/R European road numbering
- **Context-aware**: Catches "te Wuustwezel", "richting Antwerpen", etc.
- **Large file support**: Automatic chunking for files of any size
- **Legend generation**: Header explaining placeholders for AI context
- **Consistent mapping**: Same value always gets same placeholder
- **Variations handled**: `Jan de Vries` and `DE VRIES, JAN` map to same person
- **Round-trip safe**: Decode reverses encode exactly
- **Multiple strategies**: Replace, redact, mask, or hash
- **Offline**: All processing happens locally

## Limitations

- NER accuracy depends on spaCy model quality
- First names without context may not be detected
- Some edge cases may need manual review
- Non-Western names may require context-based detection (automatic)

## License

CC0 1.0 Universal - Public Domain

## Author

Based on work by [Henk van Ess](https://digitaldigging.org)
