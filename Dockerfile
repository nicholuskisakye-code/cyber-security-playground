
FROM python:3.11-slim

# Create app directory
WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . /app

# Create a non-root user for safety
RUN useradd -m appuser && chown -R appuser /app
USER appuser

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
EXPOSE 5000

CMD ["python", "app.py"]
