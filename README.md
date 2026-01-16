# AIWhisperer

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: CC0](https://img.shields.io/badge/license-CC0-green.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Version](https://img.shields.io/badge/version-0.5.0-orange.svg)](https://github.com/voelspriet/aiwhisperer/releases)

**Whisper your documents to AI—with reduced risk of exposing sensitive data.**

> *"4,713 pages. An experienced researcher would need five days to build a timeline. I did it in 20 minutes, during a coffee break."*

## Why This Tool Exists

**Problem 1: Too big to upload**

You have a 170 MB investigation file. You try cloud AI:
- ChatGPT: "Failed upload"
- Claude.ai: "Files larger than 31 MB not supported"
- Gemini: "File larger than 100 MB"

Your files are too big to fail—but too big to upload. AIWhisperer converts PDFs to text (upto 92% smaller) and splits them into chunks cloud AI can handle.

**Problem 2: Too sensitive to upload, too slow to run locally**

You have confidential documents. Local AI would be safe, but it's painfully slow—hours for what cloud AI does in minutes. So you upload to cloud AI anyway, unredacted, hoping for the best.

AIWhisperer gives you a middle path: sanitize locally, analyze in the cloud, decode locally. You get cloud AI speed with reduced exposure of sensitive data.

## How It Works

| Step | Where | What happens |
|:----:|:-----:|:-------------|
| 1 | Local | **Convert** - PDF to text (with OCR for scanned pages) |
| 2 | Local | **Split** - Break into chunks (500 pages each) |
| 3 | Local | **Encode** - Replace names with placeholders |
|   |       | `John Smith` → `PERSON_001` |
|   |       | `+31 6 12345678` → `PHONE_001` |
|   |       | Saves `mapping.json` locally |
| 4 | Cloud | **Upload** sanitized files to AI (NotebookLM, etc.) |
| 5 | Cloud | **AI analyzes** - finds patterns, builds timelines |
| 6 | Local | **Download** AI output |
| 7 | Local | **Decode** - restore real names using `mapping.json` |

**This reduces—but does not eliminate—the risk of exposing sensitive data.** Always review the sanitized output before uploading.

## What Can You Whisper to AI?

Once your documents are sanitized, whisper questions to AI:

- **Build timelines** - "Create a chronological timeline of all events"
- **Find connections** - "Who communicated with whom? Map the relationships"
- **Identify patterns** - "What phone numbers appear together? What locations overlap?"
- **Summarize** - "What are the key findings in this 4,000-page investigation?"
- **Extract data** - "List all financial transactions with dates and amounts"
- **Cross-reference** - "Which people appear in multiple documents?"

The AI works with `PERSON_001`, `PHONE_002`, `PLACE_003`. After analysis, AIWhisperer restores the real names: `PERSON_001` → `John Smith`, `PHONE_002` → `+32 489 66 70 88`, etc.

**Result:** AI-powered analysis with reduced exposure of sensitive data.

## Important Warnings

**ALWAYS CHECK THE OUTPUT BEFORE UPLOADING TO AI.**

This tool is not perfect. Detection can miss things. Before uploading any sanitized document:

1. **Review the sanitized output** - Open the file and verify sensitive data is actually replaced
2. **Use `--dry-run` first** - See what gets detected before committing
3. **Check for unique identifiers** - Job titles, rare events, or specific descriptions can still identify people:
   - BAD: `"PERSON_001, the mayor of Springfield"` → Still identifiable
   - BAD: `"PERSON_001 arrested in Europe's largest drug bust"` → The event identifies the person
   - OK: `"PERSON_001 transferred money to PERSON_002"` → Safe
4. **Test with sample data first** - Before processing real confidential documents
5. **You are responsible** - This tool assists, but YOU must verify the output is safe

**No detection is 100% accurate.** Names with unusual spelling, new patterns, or edge cases may slip through. When in doubt, manually check.

## The Story Behind This Tool

This tool was born from a real investigation: a 170-megabyte cocaine smuggling case file containing court orders, wiretap transcripts, cell tower data, arrest warrants, bank statements, and interrogation protocols.

The problem? You shouldn't upload confidential files to cloud AI. And even if you wanted to:
- ChatGPT: "Failed upload"
- Gemini: "File larger than 100 MB"
- Claude.ai: "You may not upload files larger than 31 MB"

The solution? **Encode locally → Analyze in cloud → Decode locally.**

Read the full story: **[Speed reading a massive criminal investigation with AI](https://www.digitaldigging.org/p/speed-reading-a-massive-criminal)** - *How to make sense of 4,713 pages in 20 minutes without leaking data*

## The Concept

```
BEFORE:    "On 16/10/2023, officers arrested John Smith at 123 Harbor Road.
            He was hired by Marcus Johnson."

AFTER:     "On 16/10/2023, officers arrested PERSON_001 at ADDRESS_001.
            He was hired by PERSON_002."

AI OUTPUT: "Timeline shows PERSON_001 arrested on 16/10/2023, connected to
            PERSON_002 who runs COMPANY_001, COMPANY_002 and COMPANY_003"

DECODED:   "Timeline shows John Smith arrested on 16/10/2023, connected to
            Marcus Johnson who runs Hideout 1, Hideout 2 and Hideout 3"
```

**What changes:** Names, locations, phones, emails, IBANs, vehicles, addresses
**What stays:** Structure, relationships, patterns, dates, amounts

## Quick Start

### Installation

#### Option 1: macOS App (Apple Silicon)

Download the `.dmg` installer from [Releases](https://github.com/voelspriet/aiwhisperer/releases) - no Python needed.

1. Download `AIWhisperer-x.x.x-arm64.dmg`
2. Open the DMG and run `install.command`
3. Run `aiwhisperer --help` in Terminal

Note: The app is not code-signed. On first run, right-click and select "Open" to bypass Gatekeeper.

#### Option 2: pip install (all platforms)

```bash
# Install with spaCy and OCR support (recommended)
pip install aiwhisperer[spacy,ocr]

# Download Dutch language model
python -m spacy download nl_core_news_sm

# Other languages available: en, de, fr, it, es

# Check what's installed and what's missing
aiwhisperer check
```

The `check` command shows exactly what's installed and how to fix missing dependencies:

```
$ aiwhisperer check

AIWhisperer Dependency Check
===================================
Python: 3.10.5  (OK)

PDF Conversion:
  [x] marker-pdf: Installed (best accuracy)
  [x] pymupdf: Installed
  [x] tesseract: Installed (OCR fallback)

NER Detection:
  [x] spaCy: Installed (v3.8.11)

Language Models:
  [x] nl: nl_core_news_sm
  [ ] en: en_core_web_sm
      -> Fix: python -m spacy download en_core_web_sm
```

### Command Line

**Two workflows:**

```bash
# WORKFLOW 1: Non-confidential files (just convert)
aiwhisperer convert document.pdf

# WORKFLOW 2: Confidential files (convert + sanitize in one step)
aiwhisperer convert document.pdf --sanitize
```

**Full workflow for large confidential files:**

```bash
# Step 1: Convert and sanitize (with split for large files)
aiwhisperer convert investigation.pdf --split --max-pages 500 --sanitize

# Creates:
#   investigation_part1.txt            ← Plain text
#   investigation_part1_sanitized.txt  ← Send to AI
#   investigation_part1_mapping.json   ← Keep this LOCAL

# IMPORTANT: Check sanitized files before uploading!
# Make sure no sensitive data slipped through.

# Step 2: Upload sanitized files to NotebookLM
#         Ask AI to build timeline, find patterns, etc.

# Step 3: Save AI output, then decode back to real names
aiwhisperer decode ai_analysis.txt -m investigation_part1_mapping.json

# Result: Full analysis with real names restored
```

For smaller files (under ~50MB), you can skip the `--split` flag.

### Python API

```python
from aiwhisperer import encode, decode, Mapping
from aiwhisperer.converter import convert_pdf

# Convert PDF to text
text, metadata = convert_pdf("investigation.pdf")

# Encode
sanitized, mapping = encode(text, language='nl')

# Save
open("sanitized.txt", "w").write(sanitized)
mapping.save("mapping.json")

# IMPORTANT: Review sanitized.txt before uploading!

# ... send sanitized.txt to AI, get analysis back ...

# Decode
ai_output = open("ai_analysis.txt").read()
final = decode(ai_output, mapping)
open("final_report.txt", "w").write(final)
```

## PDF Conversion

AIWhisperer includes built-in PDF to text conversion with OCR for scanned documents.

### OCR Backends

| Backend | Accuracy | Install |
|---------|----------|---------|
| **marker-pdf** (recommended) | Excellent | `pip install marker-pdf` |
| **pytesseract** (fallback) | Good | `pip install pymupdf pytesseract pdf2image` + Tesseract |

marker-pdf uses Surya OCR under the hood - currently one of the most accurate OCR solutions available.

### Usage

```bash
# Convert PDF (auto-selects best available backend)
aiwhisperer convert document.pdf

# Force specific backend
aiwhisperer convert document.pdf --backend marker

# Split large PDFs into multiple text files
aiwhisperer convert large.pdf --split --max-pages 500

# Just show PDF info
aiwhisperer convert document.pdf --info
```

### Installing Tesseract (fallback)

If marker-pdf doesn't work for you:

```bash
# macOS
brew install tesseract tesseract-lang

# Ubuntu/Debian
apt install tesseract-ocr tesseract-ocr-nld tesseract-ocr-deu tesseract-ocr-fra

# Windows: download from https://github.com/UB-Mannheim/tesseract/wiki
```

## What Gets Detected

| Category | Examples | What it catches |
|----------|----------|-----------------|
| **PERSON** | `Jan de Vries`, `El Mansouri Brahim` | Names via NER + context patterns |
| **PLACE** | `Antwerpen`, `te Wuustwezel` | Cities, "te X", "richting X" patterns |
| **PHONE** | `+32 489 66 70 88`, `052/26.08.60` | Belgian, Dutch, international formats |
| **EMAIL** | `jan@example.com` | Standard email patterns |
| **IBAN** | `BE44 3770 8065 6345` | European bank accounts |
| **VEHICLE** | `Fiat Ducato`, `BMW X5` | 50+ car brands and models |
| **ROAD** | `N133`, `A12`, `E19` | European road numbering |
| **STREET** | `Stationstraat`, `Koning Albertlaan` | Dutch/Belgian street names |
| **ADDRESS** | `Dorpstraat 31/301` | Full addresses with house numbers |
| **DOB** | `26/04/1993` (near "geboren") | Dates of birth in context |
| **ID** | `123456782` | Dutch BSN (validated), Belgian national numbers |

## FAQ

### Why not just upload to AI directly?

**Security.** Criminal investigations, medical records, legal documents—you shouldn't upload these to cloud AI. AIWhisperer lets you get AI analysis without exposing the actual data.

**Size limits.** Most chatbots can't handle large files anyway:
- ChatGPT: "Failed upload"
- Gemini: "File larger than 100 MB"
- Claude.ai: "You may not upload files larger than 31 MB"

The original workflow uses **Claude Code** (runs locally, no upload limits) for file conversion, and **NotebookLM** for analysis of the sanitized text.

### Can't AI guess who PERSON_001 is from context?

Yes, if there are unique identifiers. See the **⚠️ Important Warnings** section above. Always review the sanitized output before uploading.

### What about scanned PDFs?

AIWhisperer works on text. For scanned documents:
1. First convert PDF to text using OCR (Claude Code can help with this)
2. Then sanitize the text output
3. The original article describes processing 565 scanned pages this way

### Why 6 languages?

Each language has its own spaCy NER model trained on native text:
- `nl` Dutch - `nl_core_news_sm`
- `en` English - `en_core_web_sm`
- `de` German - `de_core_news_sm`
- `fr` French - `fr_core_news_sm`
- `it` Italian - `it_core_news_sm`
- `es` Spanish - `es_core_news_sm`

### Is this admissible in court?

**Yes.** The AI isn't evidence. It's a flashlight.

In court, you show the original data and explain how you reached your conclusion. Defense can examine those same documents. They don't need to audit the algorithm, because the algorithm didn't produce evidence—just a roadmap.

Same way Ctrl+F doesn't break chain of custody, neither does pattern recognition on anonymized data. It speeds up the investigation. It doesn't replace verification.

**Example:** Say the AI finds: *"PERSON_A met PERSON_B three days before the transfer to COMPANY_X."* That's not a conclusion you present in court. That's a hint where to look. You go back to the original documents—page 847, page 1,203, page 3,421. That's where the evidence lives. The AI helped you find where to look—in 20 minutes instead of 5 days.

### How accurate is the detection?

Detection uses multiple layers:
1. **spaCy NER** - Context-aware name/location detection
2. **Pattern matching** - High-confidence for structured data (phones, emails, IBANs)
3. **Context markers** - Catches "te Wuustwezel", "richting Antwerpen" that NER might miss

Always do a test run with `--dry-run` to see what gets detected.

### What if it misses something?

The `--dry-run` flag shows exactly what will be replaced. If something is missed:
1. Check if it's a pattern we should add
2. For one-off cases, manually edit before uploading
3. Report issues on GitHub

### Can I process multiple documents with consistent placeholders?

Yes. Reuse the same mapping:

```python
mapping = Mapping()
for doc in documents:
    sanitized, mapping = encode(doc, mapping=mapping)
# PERSON_001 refers to the same person across all documents
```

## Real-World Results

From the original investigation:
- **Input:** 170 MB PDF, 4,713 pages, 1,053,356 words
- **After conversion:** 13.8 MB text (92% smaller)
- **Processing time:** 20 minutes (vs 5 days manual)
- **Output:** Complete timeline with all connections mapped

The machine does what machines do well—pattern recognition, repetitive extraction, organizing chaos. You do what humans do well—judgment, context, and knowing when something smells wrong.

## Supported Languages

| Code | Language | Model |
|------|----------|-------|
| `nl` | Dutch | `nl_core_news_sm` |
| `en` | English | `en_core_web_sm` |
| `de` | German | `de_core_news_sm` |
| `fr` | French | `fr_core_news_sm` |
| `it` | Italian | `it_core_news_sm` |
| `es` | Spanish | `es_core_news_sm` |

## Advanced Options

### Anonymization Strategies

```bash
aiwhisperer encode doc.txt --strategy replace  # PERSON_001 (default, reversible)
aiwhisperer encode doc.txt --strategy redact   # [PERSON] (not reversible)
aiwhisperer encode doc.txt --strategy mask     # J** d* V**** (partial)
aiwhisperer encode doc.txt --strategy hash     # a1b2c3d4 (one-way)
```

### Detection Backends

```bash
aiwhisperer encode doc.txt --backend hybrid    # spaCy + patterns (default)
aiwhisperer encode doc.txt --backend patterns  # patterns only (no spaCy needed)
```

### Preview Detection

```bash
aiwhisperer encode doc.txt --dry-run  # Shows what would be replaced
aiwhisperer analyze doc.txt           # Full detection statistics
```

## Credits & Attribution

### Original Story
**[Speed reading a massive criminal investigation with AI](https://www.digitaldigging.org/p/speed-reading-a-massive-criminal)**
*How to make sense of 4,713 pages in 20 minutes without leaking data*
By Henk van Ess, January 2026

### Code Sources
- Anonymization strategies based on [mstack.nl](https://mstack.nl/blogs/anonymize-pii-llm/)
- spaCy NER integration follows [spaCy documentation](https://spacy.io/)
- BSN validation uses Dutch [11-proef algorithm](https://nl.wikipedia.org/wiki/Burgerservicenummer)
- Optional: [Microsoft Presidio](https://github.com/microsoft/presidio), [GLiNER](https://github.com/urchade/GLiNER)

### Added by Henk van Ess
- Vehicle brand/model detection
- Road number detection (N/A/E/R)
- Context-based location detection
- Context-based name detection
- Legend generation for AI context
- Large file chunking support
- Real-world testing and validation

## License

CC0 1.0 Universal - Public Domain

---

*"That's the real skill nowadays: knowing which buttons to press, and knowing when to stop pressing and start thinking."*

