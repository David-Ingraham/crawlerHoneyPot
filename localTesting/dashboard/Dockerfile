FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Set environment variables
ENV FLASK_APP=app.py
ENV PORT=8080
ENV DB_PATH=/data/bot_data.db

# Expose port
EXPOSE 8080

# Run application
CMD ["python", "-u", "app.py"]

