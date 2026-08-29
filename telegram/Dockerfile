FROM python:3.12-slim

# Pinned. An unpinned client library is a silent breaking change on the next
# rebuild, on a container whose whole job is to keep working unattended.
RUN pip install --no-cache-dir telethon==1.36.0

WORKDIR /app
COPY bot.py .
ENV TGPUSH_CONFIG=/etc/tgpush/config.ini
# -u: docker logs shows nothing at all until the buffer flushes otherwise.
ENTRYPOINT ["python", "-u", "bot.py"]
