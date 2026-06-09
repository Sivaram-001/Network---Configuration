FROM python:3.11-slim

WORKDIR /app

# Copy requirement files from backend and install them
COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files to access modules
COPY . .

# Launch command
ENTRYPOINT ["python", "mcp-server/mcp_server.py"]
