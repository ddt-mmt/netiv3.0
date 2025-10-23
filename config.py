import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'd4e3f2a1c0b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7')
    LANGUAGES = {'en': 'English'}
    
    # Gitgen specific configurations
    GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
    GITGEN_SECRET_KEY = os.environ.get('GITGEN_SECRET_KEY', 'gitgen-super-secret-key-placeholder')

    # Add other configuration variables here
