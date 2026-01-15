#!/usr/bin/env python3
"""Interactive DocSanitizer - drag and drop files to sanitize."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from docsanitizer import encode, decode
from docsanitizer.mapper import Mapping
from pathlib import Path

def main():
    print("\n" + "="*50)
    print("  DocSanitizer - Sanitize Documents for AI")
    print("="*50)
    print("\nCommands:")
    print("  1. Encode a document (sanitize)")
    print("  2. Decode AI output (restore names)")
    print("  3. Quit")
    print()
    
    while True:
        choice = input("Enter choice (1/2/3): ").strip()
        
        if choice == "1":
            print("\nDrag and drop a file here, or enter the path:")
            file_path = input("> ").strip().strip("'\"")
            
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
                continue
                
            # Read and encode
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
            
            sanitized, mapping = encode(text)
            
            # Save outputs
            path = Path(file_path)
            out_file = path.stem + "_sanitized" + path.suffix
            map_file = path.stem + "_mapping.json"
            
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(sanitized)
            mapping.save(map_file)
            
            print(f"\n✓ Sanitized: {out_file}")
            print(f"✓ Mapping:   {map_file}")
            print(f"\nDetected {len(mapping.entries)} sensitive values:")
            for ph, entry in list(mapping.entries.items())[:10]:
                print(f"  {ph}: {entry.canonical[:40]}")
            if len(mapping.entries) > 10:
                print(f"  ... and {len(mapping.entries) - 10} more")
            print()
            
        elif choice == "2":
            print("\nEnter AI output file path:")
            ai_file = input("> ").strip().strip("'\"")
            
            print("Enter mapping file path:")
            map_file = input("> ").strip().strip("'\"")
            
            if not os.path.exists(ai_file) or not os.path.exists(map_file):
                print("File not found!")
                continue
            
            with open(ai_file, 'r', encoding='utf-8') as f:
                text = f.read()
            
            mapping = Mapping.load(map_file)
            decoded = decode(text, mapping)
            
            path = Path(ai_file)
            out_file = path.stem + "_decoded" + path.suffix
            
            with open(out_file, 'w', encoding='utf-8') as f:
                f.write(decoded)
            
            print(f"\n✓ Decoded: {out_file}")
            print()
            
        elif choice == "3" or choice.lower() == "q":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
