FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 3306 6379
CMD ["python", "server.py"]
