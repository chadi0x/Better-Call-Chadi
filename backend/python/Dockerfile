FROM python:3.9-slim

WORKDIR /app

# Install system dependencies for Wapiti and lxml
RUN apt-get update && apt-get install -y \
    nmap \
    libxml2-dev \
    libxslt-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8000", "--timeout", "300", "app:app"]
