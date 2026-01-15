# DocSanitizer

**Let AI analyze your confidential documents—without leaking the data.**

> *"4,713 pages. An experienced researcher would need five days to build a timeline. I did it in 20 minutes, during a coffee break."*

## What This Tool Does

DocSanitizer lets you use AI to analyze sensitive documents (criminal investigations, medical records, legal files) **without exposing the actual data**.

**The workflow:**
1. **Encode** - Replace all names, phones, addresses with placeholders (`John Smith` → `PERSON_001`)
2. **Analyze** - Send the sanitized text to AI (NotebookLM, etc.) for analysis
3. **Decode** - The tool automatically replaces placeholders back to real names in the AI output

**The AI never sees the real data. You get the full analysis.**

## What Can AI Do With Sanitized Documents?

Once sanitized, you can ask AI to:

- **Build timelines** - "Create a chronological timeline of all events"
- **Find connections** - "Who communicated with whom? Map the relationships"
- **Identify patterns** - "What phone numbers appear together? What locations overlap?"
- **Summarize** - "What are the key findings in this 4,000-page investigation?"
- **Extract data** - "List all financial transactions with dates and amounts"
- **Cross-reference** - "Which people appear in multiple documents?"

The AI works with `PERSON_001`, `PHONE_002`, `PLACE_003`. After analysis, DocSanitizer converts the output back: `PERSON_001` → `John Smith`, `PHONE_002` → `+32 489 66 70 88`, etc.

**Result:** Full AI-powered analysis with real names—without ever uploading sensitive data.

## ⚠️ Important Warnings

**ALWAYS CHECK THE OUTPUT BEFORE UPLOADING TO AI.**

This tool is not perfect. Detection can miss things. Before uploading any sanitized document:

1. **Review the sanitized output** - Open the file and verify sensitive data is actually replaced
2. **Use `--dry-run` first** - See what gets detected before committing
3. **Check for unique identifiers** - Job titles, rare events, or specific descriptions can still identify people:
   - ❌ `"PERSON_001, the mayor of Springfield"` → Still identifiable
   - ❌ `"PERSON_001 arrested in Europe's largest drug bust"` → The event identifies the person
   - ✅ `"PERSON_001 transferred money to PERSON_002"` → Safe
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

## The Workflow

```mermaid
flowchart TB
    subgraph LOCAL1["YOUR COMPUTER (offline)"]
        A[Original Document] --> B[DocSanitizer encode]
        B --> C[Sanitized Document]
        B --> D[mapping.json]
    end

    C -->|upload| E

    subgraph CLOUD["CLOUD AI (e.g. NotebookLM)"]
        E["AI analyzes: PERSON_001 met PERSON_002..."]
        E --> F[AI finds patterns, timelines, connections]
    end

    F -->|download| G

    subgraph LOCAL2["YOUR COMPUTER (offline)"]
        G[AI Analysis Output] --> H[DocSanitizer decode]
        D -.-> H
        H --> I[Final Report with real names]
    end
```

**The AI isn't evidence. It's a flashlight.** It helps you find where to look—in 20 minutes instead of 5 days.

## Quick Start

### Installation

```bash
# Install with spaCy support (recommended)
pip install docsanitizer[spacy]

# Download Dutch language model
python -m spacy download nl_core_news_sm

# Other languages available: en, de, fr, it, es
```

### Command Line

```bash
# Step 1: Sanitize your document
docsanitizer encode investigation.txt --legend

# Creates:
#   investigation_sanitized.txt  ← Send this to AI
#   investigation_mapping.json   ← Keep this LOCAL

# Step 2: Upload sanitized file to NotebookLM/ChatGPT/Claude
#         Ask AI to build timeline, find patterns, etc.

# Step 3: Save AI output, then decode back to real names
docsanitizer decode ai_analysis.txt -m investigation_mapping.json

# Result: Full analysis with real names restored
```

### Python API

```python
from docsanitizer import encode, decode, Mapping

# Encode
text = open("investigation.txt").read()
sanitized, mapping = encode(text, language='nl')

# Save
open("sanitized.txt", "w").write(sanitized)
mapping.save("mapping.json")

# ... send sanitized.txt to AI, get analysis back ...

# Decode
ai_output = open("ai_analysis.txt").read()
final = decode(ai_output, mapping)
open("final_report.txt", "w").write(final)
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

**Security.** Criminal investigations, medical records, legal documents—you shouldn't upload these to cloud AI. DocSanitizer lets you get AI analysis without exposing the actual data.

**Size limits.** Most chatbots can't handle large files anyway:
- ChatGPT: "Failed upload"
- Gemini: "File larger than 100 MB"
- Claude.ai: "You may not upload files larger than 31 MB"

The original workflow uses **Claude Code** (runs locally, no upload limits) for file conversion, and **NotebookLM** for analysis of the sanitized text.

### Can't AI guess who PERSON_001 is from context?

Yes, if there are unique identifiers. See the **⚠️ Important Warnings** section above. Always review the sanitized output before uploading.

### What about scanned PDFs?

DocSanitizer works on text. For scanned documents:
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
docsanitizer encode doc.txt --strategy replace  # PERSON_001 (default, reversible)
docsanitizer encode doc.txt --strategy redact   # [PERSON] (not reversible)
docsanitizer encode doc.txt --strategy mask     # J** d* V**** (partial)
docsanitizer encode doc.txt --strategy hash     # a1b2c3d4 (one-way)
```

### Detection Backends

```bash
docsanitizer encode doc.txt --backend hybrid    # spaCy + patterns (default)
docsanitizer encode doc.txt --backend patterns  # patterns only (no spaCy needed)
```

### Preview Detection

```bash
docsanitizer encode doc.txt --dry-run  # Shows what would be replaced
docsanitizer analyze doc.txt           # Full detection statistics
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
