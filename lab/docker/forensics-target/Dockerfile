FROM python:3.11-slim

WORKDIR /app
COPY seed_evidence.py /app/seed_evidence.py

VOLUME ["/mnt/evidence"]
CMD ["python", "seed_evidence.py"]
