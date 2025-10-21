from flask import Flask
from config import Config

def create_app(config_class=Config):
    app = Flask(__name__)
    print("--- create_app() called ---")
    app.config.from_object(config_class)

    # Load custom tools
    import json
    import os
    try:
        custom_tools_path = os.path.join(app.root_path, '..', 'custom_tools.json')
        with open(custom_tools_path, 'r') as f:
            file_content = f.read()
            print("--- custom_tools.json content ---")
            print(file_content)
            print("--- end of content ---")
            app.config['CUSTOM_TOOLS'] = json.loads(file_content)
    except (FileNotFoundError, json.JSONDecodeError):
        app.config['CUSTOM_TOOLS'] = []

    from app.routes import web_bp, bp
    app.register_blueprint(web_bp)
    app.register_blueprint(bp)

    return app