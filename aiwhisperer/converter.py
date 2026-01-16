"""
PDF to Text Converter with OCR support.

Converts PDF files to text, handling both native PDFs and scanned documents.

Primary: marker-pdf (best accuracy, uses Surya OCR)
Fallback: PyMuPDF + pytesseract (more compatible)
"""

import os
from pathlib import Path
from typing import Optional, List, Tuple, Union


def _check_marker_available() -> bool:
    """Check if marker-pdf is installed and working."""
    try:
        from marker.converters.pdf import PdfConverter
        return True
    except Exception:
        # Catch all errors: ImportError, ValueError (numpy compat), etc.
        return False


def _check_pymupdf_available() -> bool:
    """Check if PyMuPDF is installed."""
    try:
        import fitz
        return True
    except Exception:
        return False


def _check_tesseract_available() -> bool:
    """Check if pytesseract and required components are installed."""
    try:
        import pytesseract
        from pdf2image import convert_from_path
        # Test if tesseract binary is available
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def get_available_converters() -> dict:
    """Get status of available PDF converters."""
    return {
        "marker": _check_marker_available(),
        "pymupdf": _check_pymupdf_available(),
        "tesseract": _check_tesseract_available(),
    }


def convert_with_marker(
    pdf_path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
) -> Tuple[str, dict]:
    """
    Convert PDF to text using marker-pdf (best accuracy).

    Args:
        pdf_path: Path to PDF file
        output_dir: Directory for output files (optional)

    Returns:
        Tuple of (extracted_text, metadata)
    """
    from marker.converters.pdf import PdfConverter
    from marker.models import create_model_dict

    pdf_path = Path(pdf_path)

    # Initialize converter
    models = create_model_dict()
    converter = PdfConverter(artifact_dict=models)

    # Convert
    result = converter(str(pdf_path))

    # Extract text
    text = result.markdown if hasattr(result, 'markdown') else str(result)

    metadata = {
        "converter": "marker-pdf",
        "pages": getattr(result, 'pages', None),
    }

    # Save if output_dir specified
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{pdf_path.stem}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text)
        metadata["output_file"] = str(output_file)

    return text, metadata


def convert_with_pymupdf_tesseract(
    pdf_path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    languages: str = "nld+eng+deu+fra",
    progress_callback: Optional[callable] = None,
) -> Tuple[str, dict]:
    """
    Convert PDF to text using PyMuPDF + pytesseract fallback.

    PyMuPDF extracts native text, pytesseract handles scanned pages.

    Args:
        pdf_path: Path to PDF file
        output_dir: Directory for output files (optional)
        languages: Tesseract language codes (default: Dutch+English+German+French)
        progress_callback: Optional callback(page_num, total_pages, message)

    Returns:
        Tuple of (extracted_text, metadata)
    """
    import fitz  # PyMuPDF

    pdf_path = Path(pdf_path)
    doc = fitz.open(str(pdf_path))
    total_pages = len(doc)

    all_text = []
    pages_native = 0
    pages_ocr = 0
    pages_failed = 0
    ocr_errors = []

    for page_num, page in enumerate(doc):
        if progress_callback:
            progress_callback(page_num + 1, total_pages, f"Processing page {page_num + 1}/{total_pages}")

        # Try native text extraction first
        text = page.get_text()
        native_chars = len(text.strip())

        # If page has very little text, it might be scanned - try OCR
        if native_chars < 50:
            ocr_text, ocr_error = _ocr_page(page, languages)

            if ocr_error:
                ocr_errors.append(f"Page {page_num + 1}: {ocr_error}")

            if ocr_text and len(ocr_text.strip()) > native_chars:
                text = ocr_text
                pages_ocr += 1
            elif native_chars == 0:
                # Page is completely empty even after OCR attempt
                pages_failed += 1
                if ocr_error:
                    text = f"[OCR FAILED: {ocr_error}]"
                else:
                    text = "[EMPTY PAGE - possibly image-only content]"
            else:
                pages_native += 1
        else:
            pages_native += 1

        all_text.append(f"--- Page {page_num + 1} ---\n{text}")

    doc.close()

    full_text = "\n\n".join(all_text)

    metadata = {
        "converter": "pymupdf+tesseract",
        "total_pages": total_pages,
        "native_pages": pages_native,
        "ocr_pages": pages_ocr,
        "failed_pages": pages_failed,
    }

    if ocr_errors:
        metadata["ocr_errors"] = ocr_errors
        metadata["warning"] = f"{len(ocr_errors)} pages had OCR issues"

    # Save if output_dir specified
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{pdf_path.stem}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_text)
        metadata["output_file"] = str(output_file)

    return full_text, metadata


def _ocr_page(page, languages: str = "eng") -> Tuple[Optional[str], Optional[str]]:
    """
    OCR a single page using pytesseract.

    Returns:
        Tuple of (text, error_message). If OCR succeeds, error is None.
        If OCR fails, text is None and error contains the reason.
    """
    try:
        import pytesseract
        from PIL import Image
        import io
        import fitz

        # Render page to image at higher resolution for better OCR
        # 3x zoom = 216 DPI, good balance of quality and speed
        pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
        img_data = pix.tobytes("png")
        img = Image.open(io.BytesIO(img_data))

        # Try OCR with requested languages, fall back to English only
        try:
            text = pytesseract.image_to_string(img, lang=languages)
        except pytesseract.TesseractError:
            # Language pack not installed, try English only
            try:
                text = pytesseract.image_to_string(img, lang="eng")
            except pytesseract.TesseractError as e:
                return None, f"Tesseract error: {e}"

        return text, None

    except ImportError as e:
        return None, f"OCR dependency missing: {e}"
    except Exception as e:
        return None, f"OCR failed: {e}"


def convert_pdf(
    pdf_path: Union[str, Path],
    output_dir: Optional[Union[str, Path]] = None,
    backend: str = "auto",
    languages: str = "nld+eng+deu+fra",
    split_pages: bool = False,
    max_pages_per_file: int = 500,
) -> Tuple[str, dict]:
    """
    Convert PDF to text using the best available method.

    Args:
        pdf_path: Path to PDF file
        output_dir: Directory for output files (optional)
        backend: "auto", "marker", or "tesseract"
        languages: Tesseract language codes (for tesseract backend)
        split_pages: Split output into multiple files
        max_pages_per_file: Max pages per file when splitting

    Returns:
        Tuple of (extracted_text, metadata)
    """
    pdf_path = Path(pdf_path)

    if not pdf_path.exists():
        raise FileNotFoundError(f"PDF not found: {pdf_path}")

    available = get_available_converters()

    # Select backend
    if backend == "auto":
        if available["marker"]:
            backend = "marker"
        elif available["pymupdf"] and available["tesseract"]:
            backend = "tesseract"
        elif available["pymupdf"]:
            backend = "pymupdf"
        else:
            raise ImportError(
                "No PDF converter available. Install one of:\n"
                "  pip install marker-pdf  (recommended, best accuracy)\n"
                "  pip install pymupdf pytesseract pdf2image  (fallback)"
            )

    # Convert
    if backend == "marker":
        if not available["marker"]:
            raise ImportError("marker-pdf not installed. Run: pip install marker-pdf")
        text, metadata = convert_with_marker(pdf_path, output_dir)

    elif backend == "tesseract":
        if not available["pymupdf"]:
            raise ImportError("PyMuPDF not installed. Run: pip install pymupdf")
        text, metadata = convert_with_pymupdf_tesseract(pdf_path, output_dir, languages)

    elif backend == "pymupdf":
        # PyMuPDF only, no OCR
        import fitz
        doc = fitz.open(str(pdf_path))
        all_text = []
        for page_num, page in enumerate(doc):
            page_text = page.get_text()
            all_text.append(f"--- Page {page_num + 1} ---\n{page_text}")
        doc.close()
        text = "\n\n".join(all_text)
        metadata = {
            "converter": "pymupdf",
            "total_pages": len(all_text),
            "note": "No OCR - scanned pages may be empty"
        }
        
        # Save if output_dir specified
        if output_dir:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / f"{pdf_path.stem}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(text)
            metadata["output_file"] = str(output_file)

    else:
        raise ValueError(f"Unknown backend: {backend}")

    # Split if requested
    if split_pages and output_dir:
        _split_text(text, output_dir, pdf_path.stem, max_pages_per_file)
        metadata["split"] = True
        metadata["max_pages_per_file"] = max_pages_per_file

    return text, metadata


def _split_text(
    text: str,
    output_dir: Path,
    base_name: str,
    max_pages: int = 500,
) -> List[Path]:
    """Split text into multiple files based on page markers."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Split by page markers
    import re
    pages = re.split(r'--- Page \d+ ---', text)
    pages = [p.strip() for p in pages if p.strip()]

    if not pages:
        # No page markers, split by character count
        chunk_size = 500000  # ~500KB per file
        pages = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

    # Group pages
    files = []
    for i in range(0, len(pages), max_pages):
        chunk = pages[i:i+max_pages]
        chunk_text = "\n\n".join(chunk)

        file_num = i // max_pages + 1
        output_file = output_dir / f"{base_name}_part{file_num}.txt"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(chunk_text)

        files.append(output_file)

    return files


def get_pdf_info(pdf_path: Union[str, Path]) -> dict:
    """Get basic info about a PDF file."""
    pdf_path = Path(pdf_path)

    info = {
        "path": str(pdf_path),
        "size_mb": pdf_path.stat().st_size / (1024 * 1024),
    }

    if _check_pymupdf_available():
        import fitz
        doc = fitz.open(str(pdf_path))
        info["pages"] = len(doc)
        info["title"] = doc.metadata.get("title", "")
        info["author"] = doc.metadata.get("author", "")
        doc.close()

    return info
