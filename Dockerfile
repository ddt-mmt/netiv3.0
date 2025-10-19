# Use an official lightweight Python image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 5004

# Command to run the application using Gunicorn for production
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5004", "app:create_app()"]
