"""
AIWhisperer GUI - Google Drive Integration

Upload converted text files to Google Drive for easy use with NotebookLM and other AI tools.
"""

import os
import json
from pathlib import Path

# Google Drive API scopes
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# Token storage location
TOKEN_PATH = Path.home() / '.aiwhisperer' / 'gdrive_token.json'
CREDENTIALS_PATH = Path.home() / '.aiwhisperer' / 'gdrive_credentials.json'


def get_credentials_path():
    """Get the path to the credentials file."""
    return CREDENTIALS_PATH


def get_token_path():
    """Get the path to the token file."""
    return TOKEN_PATH


def is_authenticated():
    """Check if user is authenticated with Google Drive."""
    if not TOKEN_PATH.exists():
        return False
    
    try:
        from google.oauth2.credentials import Credentials
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
        return creds and creds.valid
    except Exception:
        return False


def authenticate():
    """
    Authenticate with Google Drive.
    
    Returns credentials object or None if authentication fails.
    """
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
    except ImportError:
        raise ImportError(
            "Google Drive dependencies not installed.\n"
            "Install with: pip install google-api-python-client google-auth-oauthlib"
        )
    
    creds = None
    
    # Load existing token
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
    
    # Refresh or get new credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Check for credentials file
            if not CREDENTIALS_PATH.exists():
                raise FileNotFoundError(
                    f"Google Drive credentials not found at {CREDENTIALS_PATH}\n\n"
                    "To set up Google Drive integration:\n"
                    "1. Go to https://console.cloud.google.com/\n"
                    "2. Create a new project or select existing\n"
                    "3. Enable the Google Drive API\n"
                    "4. Create OAuth 2.0 credentials (Desktop app)\n"
                    "5. Download the credentials JSON file\n"
                    f"6. Save it as: {CREDENTIALS_PATH}"
                )
            
            flow = InstalledAppFlow.from_client_secrets_file(
                str(CREDENTIALS_PATH), SCOPES
            )
            creds = flow.run_local_server(port=0)
        
        # Save token for future use
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_PATH, 'w') as token:
            token.write(creds.to_json())
    
    return creds


def get_drive_service():
    """Get authenticated Google Drive service."""
    try:
        from googleapiclient.discovery import build
    except ImportError:
        raise ImportError(
            "Google Drive dependencies not installed.\n"
            "Install with: pip install google-api-python-client google-auth-oauthlib"
        )
    
    creds = authenticate()
    service = build('drive', 'v3', credentials=creds)
    return service


def upload_to_drive(content, filename, folder_id=None):
    """
    Upload text content to Google Drive.
    
    Args:
        content: Text content to upload
        filename: Name for the file in Drive
        folder_id: Optional folder ID to upload to
    
    Returns:
        File ID of the uploaded file
    """
    try:
        from googleapiclient.http import MediaInMemoryUpload
    except ImportError:
        raise ImportError(
            "Google Drive dependencies not installed.\n"
            "Install with: pip install google-api-python-client google-auth-oauthlib"
        )
    
    service = get_drive_service()
    
    # File metadata
    file_metadata = {'name': filename}
    if folder_id:
        file_metadata['parents'] = [folder_id]
    
    # Create media
    media = MediaInMemoryUpload(
        content.encode('utf-8'),
        mimetype='text/plain',
        resumable=True
    )
    
    # Upload
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, name, webViewLink'
    ).execute()
    
    return file.get('id')


def upload_file_to_drive(file_path, folder_id=None):
    """
    Upload a file to Google Drive.
    
    Args:
        file_path: Path to the file to upload
        folder_id: Optional folder ID to upload to
    
    Returns:
        File ID of the uploaded file
    """
    try:
        from googleapiclient.http import MediaFileUpload
    except ImportError:
        raise ImportError(
            "Google Drive dependencies not installed.\n"
            "Install with: pip install google-api-python-client google-auth-oauthlib"
        )
    
    service = get_drive_service()
    file_path = Path(file_path)
    
    # File metadata
    file_metadata = {'name': file_path.name}
    if folder_id:
        file_metadata['parents'] = [folder_id]
    
    # Determine mimetype
    suffix = file_path.suffix.lower()
    mimetypes = {
        '.txt': 'text/plain',
        '.json': 'application/json',
        '.pdf': 'application/pdf',
    }
    mimetype = mimetypes.get(suffix, 'application/octet-stream')
    
    # Create media
    media = MediaFileUpload(
        str(file_path),
        mimetype=mimetype,
        resumable=True
    )
    
    # Upload
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, name, webViewLink'
    ).execute()
    
    return file.get('id')


def list_files(max_results=10):
    """
    List recent files in Google Drive.
    
    Args:
        max_results: Maximum number of files to return
    
    Returns:
        List of file dictionaries with id, name, mimeType
    """
    service = get_drive_service()
    
    results = service.files().list(
        pageSize=max_results,
        fields="files(id, name, mimeType, modifiedTime)"
    ).execute()
    
    return results.get('files', [])


def create_folder(name, parent_id=None):
    """
    Create a folder in Google Drive.
    
    Args:
        name: Folder name
        parent_id: Optional parent folder ID
    
    Returns:
        Folder ID
    """
    service = get_drive_service()
    
    file_metadata = {
        'name': name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        file_metadata['parents'] = [parent_id]
    
    folder = service.files().create(
        body=file_metadata,
        fields='id'
    ).execute()
    
    return folder.get('id')


def get_or_create_aiwhisperer_folder():
    """
    Get or create an 'AIWhisperer' folder in Google Drive.
    
    Returns:
        Folder ID
    """
    service = get_drive_service()
    
    # Search for existing folder
    results = service.files().list(
        q="name='AIWhisperer' and mimeType='application/vnd.google-apps.folder' and trashed=false",
        fields="files(id)"
    ).execute()
    
    files = results.get('files', [])
    if files:
        return files[0]['id']
    
    # Create new folder
    return create_folder('AIWhisperer')


def setup_credentials_dialog():
    """
    Show instructions for setting up Google Drive credentials.
    
    Returns a string with setup instructions.
    """
    return f"""
Google Drive Setup Instructions
================================

To enable Google Drive integration, you need to create OAuth credentials:

1. Go to https://console.cloud.google.com/

2. Create a new project (or select an existing one)

3. Enable the Google Drive API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google Drive API"
   - Click "Enable"

4. Create OAuth credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Desktop app" as the application type
   - Give it a name (e.g., "AIWhisperer")
   - Click "Create"

5. Download the credentials:
   - Click the download button next to your new credential
   - Save the file as: {CREDENTIALS_PATH}

6. Restart AIWhisperer and try uploading again.

The first time you upload, a browser window will open for you to
authorize AIWhisperer to access your Google Drive.
"""
