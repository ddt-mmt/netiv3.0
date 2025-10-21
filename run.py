from app import create_app

app = create_app()

if __name__ == '__main__':
    # Note: host='0.0.0.0' is a security risk for development as it exposes the server.
    # Changed to '127.0.0.1' to restrict access to the local machine.
    app.run(host='127.0.0.1', port=5004, debug=True)