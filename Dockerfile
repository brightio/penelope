FROM python:3.12-slim
RUN apt-get update && apt-get install -y iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY penelope.py .
ENTRYPOINT ["python", "penelope.py"]