"""
Command-line interface for AIWhisperer.

Usage:
    aiwhisperer encode document.txt
    aiwhisperer decode ai_output.txt --mapping mapping.json
"""

import sys
from pathlib import Path

try:
    import click
except ImportError:
    print("Click not installed. Run: pip install click")
    print("Or use the Python API directly: from aiwhisperer import encode, decode")
    sys.exit(1)

from . import __version__
from .encoder import encode, encode_file, get_statistics, generate_legend
from .decoder import decode, decode_file
from .mapper import Mapping


@click.group()
@click.version_option(version=__version__)
def cli():
    """AIWhisperer - PDF to text with optional sanitization for AI analysis.

    TWO WORKFLOWS:

    1. Non-confidential files (just convert PDF to text):

       aiwhisperer convert document.pdf

    2. Confidential files (convert + sanitize sensitive data):

       aiwhisperer convert document.pdf --sanitize

    The sanitization reduces the risk of exposing sensitive data when
    uploading to cloud AI services.
    """
    pass


@cli.command('encode')
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), help='Output file for sanitized text')
@click.option('-m', '--mapping', type=click.Path(), help='Output file for mapping JSON')
@click.option('-l', '--language', default='nl',
              help='Language: nl, en, de, fr, it, es (default: nl)')
@click.option('-s', '--strategy', type=click.Choice(['replace', 'redact', 'mask', 'hash']),
              default='replace', help='Anonymization strategy (default: replace)')
@click.option('-b', '--backend', type=click.Choice(['hybrid', 'patterns']),
              default='hybrid', help='Detection backend (default: hybrid)')
@click.option('--dry-run', is_flag=True, help='Show what would be replaced without writing')
@click.option('--stats', is_flag=True, help='Show statistics after encoding')
@click.option('--legend/--no-legend', default=True, help='Add legend header for AI context (default: on)')
def encode_cmd(input_file, output, mapping, language, strategy, backend, dry_run, stats, legend):
    """
    Sanitize a document by replacing PII with placeholders.

    Detects and replaces: names, locations, emails, phones, IBANs, BSN, dates.
    Supports 6 languages: Dutch, English, German, French, Italian, Spanish.

    Examples:

        aiwhisperer encode document.txt

        aiwhisperer encode document.txt -l en

        aiwhisperer encode document.txt -o sanitized.txt -m mapping.json

        aiwhisperer encode document.txt --strategy mask

        aiwhisperer encode document.txt --dry-run
    """
    input_path = Path(input_file)

    # Default output paths
    if not output:
        output = input_path.stem + '_sanitized' + input_path.suffix
    if not mapping:
        mapping = input_path.stem + '_mapping.json'

    click.echo(f"Encoding: {input_file}")
    click.echo(f"Backend: {backend}, Strategy: {strategy}, Language: {language}")

    # Read and encode
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read()

    sanitized, mapping_obj = encode(text, backend=backend, strategy=strategy, language=language)

    if dry_run:
        click.echo("\n--- DRY RUN - Detected sensitive values ---\n")
        for placeholder, entry in mapping_obj.entries.items():
            click.echo(f"  {placeholder}: {entry.canonical}")
        click.echo(f"\nTotal: {len(mapping_obj.entries)} unique values")
        click.echo("\nNo files written (dry run)")
        return

    # Add legend header if requested (default: on)
    if legend:
        legend_text = generate_legend(mapping_obj)
        sanitized = legend_text + sanitized

    # Write outputs
    with open(output, 'w', encoding='utf-8') as f:
        f.write(sanitized)

    mapping_obj.save(mapping)

    click.echo(f"Sanitized: {output}")
    click.echo(f"Mapping:   {mapping}")
    if legend:
        click.echo("Legend:    Included (helps AI understand placeholders)")

    if stats:
        click.echo("\n--- Statistics ---")
        stat_dict = get_statistics(mapping_obj)
        click.echo(f"Total unique values: {stat_dict['total_unique_values']}")
        click.echo(f"Total occurrences:   {stat_dict['total_occurrences']}")
        for cat, cat_stats in stat_dict['by_category'].items():
            click.echo(f"\n{cat}:")
            click.echo(f"  Unique: {cat_stats['unique']}")
            click.echo(f"  Occurrences: {cat_stats['occurrences']}")
            for example in cat_stats['examples']:
                click.echo(f"    {example}")


@cli.command('decode')
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-m', '--mapping', type=click.Path(exists=True), required=True,
              help='Mapping JSON file from encoding')
@click.option('-o', '--output', type=click.Path(), help='Output file for decoded text')
def decode_cmd(input_file, mapping, output):
    """
    Decode placeholders back to original values.

    Use this on AI output to restore real names/values.

    Examples:

        aiwhisperer decode ai_output.txt -m mapping.json

        aiwhisperer decode ai_output.txt -m mapping.json -o final_report.txt
    """
    input_path = Path(input_file)

    # Default output path
    if not output:
        output = input_path.stem + '_decoded' + input_path.suffix

    click.echo(f"Decoding: {input_file}")
    click.echo(f"Using mapping: {mapping}")

    decoded = decode_file(input_path, mapping, output)

    click.echo(f"Output: {output}")


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
def analyze(input_file):
    """
    Analyze a document for sensitive data without encoding.

    Shows what would be detected and replaced.
    """
    from .detectors import detect_all

    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()

    matches = detect_all(text)

    click.echo(f"\nAnalyzing: {input_file}")
    click.echo(f"File size: {len(text):,} characters\n")

    # Group by category
    by_category = {}
    for match in matches:
        if match.category not in by_category:
            by_category[match.category] = []
        by_category[match.category].append(match)

    for category, cat_matches in sorted(by_category.items()):
        click.echo(f"\n{category} ({len(cat_matches)} found):")
        # Show first 5 examples
        for match in cat_matches[:5]:
            click.echo(f"  - {match.text}")
        if len(cat_matches) > 5:
            click.echo(f"  ... and {len(cat_matches) - 5} more")

    click.echo(f"\n\nTotal: {len(matches)} sensitive values detected")


@cli.command()
@click.argument('mapping_file', type=click.Path(exists=True))
def show_mapping(mapping_file):
    """Show contents of a mapping file."""
    mapping = Mapping.load(mapping_file)

    click.echo(f"\nMapping: {mapping_file}")
    click.echo(f"Version: {mapping.version}")
    click.echo(f"Created: {mapping.created}")
    click.echo(f"\nEntries ({len(mapping.entries)}):\n")

    for placeholder, entry in sorted(mapping.entries.items()):
        click.echo(f"  {placeholder}:")
        click.echo(f"    Canonical: {entry.canonical}")
        if len(entry.variations) > 1:
            click.echo(f"    Variations: {entry.variations}")
        click.echo(f"    Occurrences: {entry.occurrences}")


@cli.command('convert')
@click.argument('pdf_file', type=click.Path(exists=True))
@click.option('-o', '--output-dir', type=click.Path(), help='Output directory for text files')
@click.option('-b', '--backend', type=click.Choice(['auto', 'marker', 'tesseract']),
              default='auto', help='OCR backend: auto, marker (best), tesseract (fallback)')
@click.option('--split/--no-split', default=False, help='Split into multiple files')
@click.option('--max-pages', default=500, help='Max pages per file when splitting (default: 500)')
@click.option('--info', is_flag=True, help='Just show PDF info, do not convert')
@click.option('--sanitize', is_flag=True, help='Also sanitize the output (for confidential files)')
@click.option('-l', '--language', default='nl',
              help='Language for sanitization: nl, en, de, fr, it, es (default: nl)')
@click.option('--legend/--no-legend', default=True, help='Add legend header when sanitizing (default: on)')
def convert_cmd(pdf_file, output_dir, backend, split, max_pages, info, sanitize, language, legend):
    """
    Convert PDF to text with OCR support.

    TWO WORKFLOWS:

    1. Non-confidential files (just convert):

        aiwhisperer convert document.pdf

    2. Confidential files (convert + sanitize):

        aiwhisperer convert document.pdf --sanitize

    The --sanitize flag detects and replaces sensitive data (names, places,
    emails, phones, etc.) creating a mapping file to restore them later.

    More examples:

        aiwhisperer convert document.pdf -o ./output/

        aiwhisperer convert document.pdf --backend marker

        aiwhisperer convert large.pdf --split --max-pages 500

        aiwhisperer convert document.pdf --sanitize -l en

        aiwhisperer convert document.pdf --info
    """
    from .converter import convert_pdf, get_pdf_info, get_available_converters

    pdf_path = Path(pdf_file)

    # Show available converters
    available = get_available_converters()
    click.echo(f"\nAvailable converters:")
    click.echo(f"  marker-pdf: {'yes' if available['marker'] else 'no (pip install marker-pdf)'}")
    click.echo(f"  tesseract:  {'yes' if available['tesseract'] else 'no (pip install pymupdf pytesseract pdf2image)'}")

    # Just show info
    if info:
        pdf_info = get_pdf_info(pdf_file)
        click.echo(f"\nPDF Info:")
        click.echo(f"  File: {pdf_info['path']}")
        click.echo(f"  Size: {pdf_info['size_mb']:.1f} MB")
        if 'pages' in pdf_info:
            click.echo(f"  Pages: {pdf_info['pages']}")
        if pdf_info.get('title'):
            click.echo(f"  Title: {pdf_info['title']}")
        return

    # Default output directory
    if not output_dir:
        output_dir = pdf_path.parent

    click.echo(f"\nConverting: {pdf_file}")
    click.echo(f"Backend: {backend}")
    click.echo(f"Output: {output_dir}")

    try:
        text, metadata = convert_pdf(
            pdf_file,
            output_dir=output_dir,
            backend=backend,
            split_pages=split,
            max_pages_per_file=max_pages,
        )

        click.echo(f"\nConversion done!")
        click.echo(f"Converter used: {metadata.get('converter', 'unknown')}")
        if 'total_pages' in metadata:
            click.echo(f"Pages: {metadata['total_pages']} ({metadata.get('native_pages', 0)} native, {metadata.get('ocr_pages', 0)} OCR)")
        if 'output_file' in metadata:
            click.echo(f"Output: {metadata['output_file']}")
        click.echo(f"Text length: {len(text):,} characters")

        # If sanitize flag is set, run encoding on the converted text
        if sanitize:
            click.echo(f"\n--- Sanitizing (language: {language}) ---")

            sanitized_text, mapping_obj = encode(text, backend='hybrid', strategy='replace', language=language)

            # Add legend header if requested
            if legend:
                legend_text = generate_legend(mapping_obj)
                sanitized_text = legend_text + sanitized_text

            # Save sanitized output
            output_file = Path(metadata.get('output_file', pdf_path.stem + '.txt'))
            sanitized_file = output_file.parent / (output_file.stem + '_sanitized.txt')
            mapping_file = output_file.parent / (output_file.stem + '_mapping.json')

            with open(sanitized_file, 'w', encoding='utf-8') as f:
                f.write(sanitized_text)
            mapping_obj.save(str(mapping_file))

            click.echo(f"Sanitized: {sanitized_file}")
            click.echo(f"Mapping:   {mapping_file}")
            click.echo(f"Entities:  {len(mapping_obj.entries)} unique values replaced")
            if legend:
                click.echo("Legend:    Included (helps AI understand placeholders)")

            click.echo(f"\nWorkflow complete! Upload {sanitized_file} to your AI.")
            click.echo(f"Then decode the AI output: aiwhisperer decode ai_output.txt -m {mapping_file}")
        else:
            click.echo(f"\nNext step: aiwhisperer encode {metadata.get('output_file', pdf_path.stem + '.txt')}")
            click.echo(f"Or for confidential files, use: aiwhisperer convert {pdf_file} --sanitize")

    except ImportError as e:
        click.echo(f"\nError: {e}")
        click.echo("\nInstall a converter:")
        click.echo("  pip install marker-pdf          (recommended, best accuracy)")
        click.echo("  pip install pymupdf pytesseract pdf2image  (fallback)")
        sys.exit(1)
    except Exception as e:
        click.echo(f"\nError: {e}")
        sys.exit(1)


@cli.command()
def check():
    """
    Check installed dependencies and show what's missing.

    Helps diagnose installation issues with clear fix instructions.

    Example:

        aiwhisperer check
    """
    import platform

    click.echo("\nAIWhisperer Dependency Check")
    click.echo("=" * 32)

    # Python version
    py_version = platform.python_version()
    py_major, py_minor = int(py_version.split('.')[0]), int(py_version.split('.')[1])
    click.echo(f"\nPython: {py_version}", nl=False)
    if py_minor < 10:
        click.echo("  (marker-pdf needs 3.10+)")
    else:
        click.echo("  (OK)")

    # PDF Conversion
    click.echo("\nPDF Conversion:")
    from .converter import get_available_converters
    converters = get_available_converters()

    # marker-pdf
    if converters['marker']:
        click.echo("  [x] marker-pdf: Installed (best accuracy)")
    else:
        if py_minor < 10:
            click.echo("  [ ] marker-pdf: Requires Python 3.10+")
        else:
            click.echo("  [ ] marker-pdf: Not installed")
            click.echo("      -> Fix: pip install marker-pdf")

    # pymupdf
    if converters['pymupdf']:
        click.echo("  [x] pymupdf: Installed")
    else:
        click.echo("  [ ] pymupdf: Not installed")
        click.echo("      -> Fix: pip install pymupdf")

    # tesseract
    if converters['tesseract']:
        click.echo("  [x] tesseract: Installed (OCR fallback)")
    else:
        click.echo("  [ ] tesseract: Not found")
        click.echo("      -> Fix: pip install pytesseract pdf2image")
        click.echo("      -> Also: brew install tesseract tesseract-lang  (macOS)")
        click.echo("               apt install tesseract-ocr  (Linux)")

    # NER Detection
    click.echo("\nNER Detection:")

    # spaCy
    spacy_ok = False
    try:
        import spacy
        spacy_ok = True
        click.echo(f"  [x] spaCy: Installed (v{spacy.__version__})")
    except ImportError:
        click.echo("  [ ] spaCy: Not installed")
        click.echo("      -> Fix: pip install spacy")

    # Language models
    if spacy_ok:
        click.echo("\nLanguage Models:")
        models = {
            'nl': 'nl_core_news_sm',
            'en': 'en_core_web_sm',
            'de': 'de_core_news_sm',
            'fr': 'fr_core_news_sm',
            'it': 'it_core_news_sm',
            'es': 'es_core_news_sm',
        }
        any_model = False
        for lang, model in models.items():
            try:
                spacy.load(model)
                click.echo(f"  [x] {lang}: {model}")
                any_model = True
            except OSError:
                click.echo(f"  [ ] {lang}: {model}")
                click.echo(f"      -> Fix: python -m spacy download {model}")

        if not any_model:
            click.echo("\n  No language models installed!")
            click.echo("  Install at least one: python -m spacy download nl_core_news_sm")

    # Summary
    click.echo("\n" + "-" * 35)

    if converters['marker'] or (converters['pymupdf'] and converters['tesseract']):
        click.echo("PDF conversion: Ready")
    elif converters['pymupdf']:
        click.echo("PDF conversion: Basic (no OCR for scanned pages)")
    else:
        click.echo("PDF conversion: Not available")

    if spacy_ok:
        click.echo("NER detection: Ready (spaCy)")
    else:
        click.echo("NER detection: Pattern-only mode (use --backend patterns)")

    click.echo("")


def main():
    """Entry point."""
    cli()


if __name__ == '__main__':
    main()
