FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY bot_parser.py .
COPY bot_signatures.json .

# Run parser
CMD ["python", "-u", "bot_parser.py"]

