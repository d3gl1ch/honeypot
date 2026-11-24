FROM python:3.12-slim

WORKDIR /app

# сначала зависимости, чтобы докер кэшировал этот слой
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot
COPY configs ./configs

# обычный пользователь вместо root, данные лежат в /data
RUN useradd -m hp && mkdir /data && chown hp /data
USER hp

EXPOSE 2222 8080 2323

CMD ["python", "-m", "honeypot", "--key", "/data/ssh_host_key", "--db", "/data/events.db", "--log", "/data/events.jsonl", "--quarantine", "/data/quarantine", "--telnet-port", "2323"]