# Examples

Sample files showing AIWhisperer in action.

## Files

| File | Description |
|------|-------------|
| `sample_before.txt` | Original document with sensitive data |
| `sample_after_sanitized.txt` | Same document after encoding - ready to upload to AI |
| `sample_mapping.json` | Mapping file (keep local!) - used to decode AI output |

## Try it yourself

```bash
# Encode the sample
aiwhisperer encode sample_before.txt --legend

# This creates:
#   sample_before_sanitized.txt
#   sample_before_mapping.json

# After AI analysis, decode:
aiwhisperer decode ai_output.txt -m sample_before_mapping.json
```

## What got detected

In this sample, AIWhisperer detected:
- 6 person names
- 5 locations
- 2 street names
- 2 phone numbers
- 2 email addresses
- 1 IBAN
- 1 company name
- 2 vehicle types

The dates, amounts, and document structure remain intact for AI analysis.
