FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y openssh-client && apt-get clean

COPY . .

RUN ssh-keygen -t rsa -b 3072 -f server.key -N ""

EXPOSE 2222

CMD ["python", "honeypot.py"]
