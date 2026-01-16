# macOS DMG Packaging for AIWhisperer

This directory contains the configuration and scripts needed to build a macOS `.dmg` installer for AIWhisperer.

## Overview

The packaging process creates a standalone macOS executable that can be distributed without requiring users to install Python or any dependencies. The executable is packaged into a `.dmg` disk image for easy installation.

## Building Locally

### Prerequisites

- macOS (the build scripts only work on macOS)
- Python 3.9 or later
- pip (Python package manager)

### Quick Build

Run the build script from the project root:

```bash
./packaging/macos/build_dmg.sh
```

This will:
1. Install PyInstaller and dependencies
2. Build a standalone executable
3. Create a `.dmg` file in `dist/`

### Manual Build Steps

If you prefer to run the steps manually:

```bash
# Install PyInstaller
pip install pyinstaller

# Install aiwhisperer with spaCy support
pip install -e ".[spacy]"

# Download spaCy models (optional, for better detection)
python -m spacy download nl_core_news_sm
python -m spacy download en_core_web_sm

# Build the executable
pyinstaller packaging/macos/aiwhisperer.spec --clean --noconfirm

# The executable will be at dist/aiwhisperer
```

To create the DMG manually:

```bash
# Install create-dmg (optional, for fancy DMG)
brew install create-dmg

# Create DMG
create-dmg \
  --volname "AIWhisperer" \
  --window-size 600 400 \
  dist/AIWhisperer.dmg \
  dist/aiwhisperer
```

Or use hdiutil for a basic DMG:

```bash
mkdir -p dist/dmg_contents
cp dist/aiwhisperer dist/dmg_contents/
hdiutil create -volname "AIWhisperer" -srcfolder dist/dmg_contents -ov -format UDZO dist/AIWhisperer.dmg
```

## GitHub Actions

The repository includes a GitHub Actions workflow that automatically builds DMGs for both Intel (x86_64) and Apple Silicon (arm64) Macs.

### Triggering a Build

1. **Manual trigger**: Go to Actions > "Build macOS DMG" > "Run workflow"
2. **Tag release**: Push a version tag (e.g., `v0.5.0`) to trigger a build and create a draft release
3. **Pull request**: Changes to relevant files will trigger a test build

### Downloading Artifacts

After a successful build, download the DMG files from the workflow run's "Artifacts" section.

## Files

- `aiwhisperer.spec` - PyInstaller specification file defining how to build the executable
- `build_dmg.sh` - Shell script to automate the entire build process
- `icon.icns` - (Optional) macOS icon file for the application

## Customization

### Adding an Icon

To add a custom icon to the DMG:

1. Create an `.icns` file (macOS icon format)
2. Save it as `packaging/macos/icon.icns`
3. The build scripts will automatically use it

You can convert a PNG to ICNS using:

```bash
# Create iconset directory
mkdir icon.iconset

# Add various sizes (required sizes: 16, 32, 128, 256, 512)
sips -z 16 16 icon.png --out icon.iconset/icon_16x16.png
sips -z 32 32 icon.png --out icon.iconset/icon_16x16@2x.png
sips -z 32 32 icon.png --out icon.iconset/icon_32x32.png
sips -z 64 64 icon.png --out icon.iconset/icon_32x32@2x.png
sips -z 128 128 icon.png --out icon.iconset/icon_128x128.png
sips -z 256 256 icon.png --out icon.iconset/icon_128x128@2x.png
sips -z 256 256 icon.png --out icon.iconset/icon_256x256.png
sips -z 512 512 icon.png --out icon.iconset/icon_256x256@2x.png
sips -z 512 512 icon.png --out icon.iconset/icon_512x512.png
sips -z 1024 1024 icon.png --out icon.iconset/icon_512x512@2x.png

# Convert to icns
iconutil -c icns icon.iconset -o icon.icns
```

### Including Additional Dependencies

The default build excludes heavy optional dependencies (torch, transformers, etc.) to keep the executable size manageable. If you need these:

1. Edit `aiwhisperer.spec`
2. Remove the dependency from the `excludes` list
3. Add any necessary hidden imports

Note: Including ML dependencies will significantly increase the executable size.

## Troubleshooting

### "App is damaged" error on macOS

If users see this error when opening the DMG or running the executable, they need to remove the quarantine attribute:

```bash
xattr -cr /path/to/aiwhisperer
```

Or right-click the app and select "Open" to bypass Gatekeeper.

### Missing dependencies at runtime

If the executable fails with import errors:

1. Check that the module is listed in `hiddenimports` in the spec file
2. Rebuild with `--debug all` to see detailed import information:
   ```bash
   pyinstaller packaging/macos/aiwhisperer.spec --debug all
   ```

### Build fails on Apple Silicon

Ensure you're using a Python version that supports ARM64. Python 3.9+ from python.org or Homebrew should work.

## Distribution

The built DMG can be distributed directly to users. For wider distribution, consider:

1. **Code signing**: Sign the executable with an Apple Developer certificate
2. **Notarization**: Submit to Apple for notarization to avoid Gatekeeper warnings
3. **Homebrew**: Create a Homebrew formula for easy installation

### Code Signing (Optional)

```bash
codesign --sign "Developer ID Application: Your Name" --options runtime dist/aiwhisperer
```

### Notarization (Optional)

```bash
# Create a ZIP for notarization
ditto -c -k --keepParent dist/aiwhisperer aiwhisperer.zip

# Submit for notarization
xcrun notarytool submit aiwhisperer.zip --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID --password YOUR_APP_PASSWORD --wait

# Staple the notarization ticket
xcrun stapler staple dist/aiwhisperer
```
