FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        less \
        groff \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir awscli policy_sentry

RUN useradd -m appuser

USER appuser
WORKDIR /home/appuser/aws-third-party-access
COPY requirements.txt .

RUN python -m venv /home/appuser/.venv && \
    . /home/appuser/.venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt


RUN echo "source /home/appuser/.venv/bin/activate" >> /home/appuser/.bashrc
RUN echo "eval \"$(_POLICY_SENTRY_COMPLETE=source policy_sentry)\"" >> /home/appuser/.bashrc
CMD ["bash", "--login"]
