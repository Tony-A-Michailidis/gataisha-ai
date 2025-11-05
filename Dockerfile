FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cato_agent.py .
COPY cato_ai_enhanced.py .
COPY dashboard.py .
COPY cato_enhanced_dashboard.py .
COPY static/ ./static/

# Create evidence directory
RUN mkdir -p /app/evidence

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "cato_enhanced_dashboard:app", "--host", "0.0.0.0", "--port", "8000"]