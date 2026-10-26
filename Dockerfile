FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    nodejs \
    npm \
    supervisor \
    build-essential \
    python3-venv \
    && npm install -g pnpm \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install -i /usr/local/aws-cli -b /usr/local/bin \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

WORKDIR /app/webapp/backend
RUN python3 -m venv /app/webapp/backend/.venv && \
    /app/webapp/backend/.venv/bin/python -m pip install --upgrade pip && \
    /app/webapp/backend/.venv/bin/python -m pip install --no-cache-dir -r requirements.txt

WORKDIR /app/webapp/frontend
RUN pnpm install

RUN mkdir -p /app/webapp/backend/data && \
    useradd --create-home --uid 1000 app && \
    chown -R app:app /app
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

USER app
ENV HOME=/home/app
WORKDIR /app
EXPOSE 8000 5173
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
