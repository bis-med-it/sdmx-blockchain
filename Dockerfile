FROM python:3.11-slim

# Keep python output unbuffered in container logs
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      build-essential \
      gcc \
      libxml2-dev \
      libxslt1-dev \
      zlib1g-dev \
      ca-certificates \
      && rm -rf /var/lib/apt/lists/*

# Change working directory
WORKDIR /code

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ /code/app/
COPY wait-for-keycloak.sh .
# Ensure Unix line endings and make executable
RUN sed -i 's/\r$//' wait-for-keycloak.sh && chmod +x wait-for-keycloak.sh

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser

# Adjusting read access rights to 
RUN chown -R appuser:appuser /code
RUN mkdir -p /home/appuser/.streamlit
RUN chown -R appuser:appuser /home/appuser/.streamlit
RUN chmod 755 /home/appuser/.streamlit

RUN chgrp -R 0 /home /home/appuser \
      && chmod -R g+rwX /home /home/appuser \
      && chmod -R g+rwX /code /code/app

USER appuser

ENV HOME=/home/appuser

# Optional: disable usage stats
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]