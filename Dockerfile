# Runtime proof of the unidirectional constraint.
#
#   docker build -t sih26145 .
#   docker run --rm --network none -v "$PWD/data:/data:ro" sih26145 /data/pcaps/mixed.pcap
#
# `--network none` gives the container no interfaces but loopback, and the
# capture is mounted read-only. If any part of the detection path needed a
# socket, a name lookup, or a write back to the input, the run would fail here
# rather than in production. It produces the same alerts as the host run.
FROM python:3.13-slim

WORKDIR /app

# Only the detection path's dependencies -- no fastapi, no scapy, no HTTP client.
COPY requirements-detect.txt .
RUN pip install --no-cache-dir -r requirements-detect.txt

COPY ingest/ ingest/
COPY features/ features/
COPY detectors/ detectors/
COPY alerts/ alerts/
COPY tools/ tools/
COPY engine.py .
COPY models/ models/

# Non-root: the process has no business owning anything it reads.
RUN useradd --create-home --shell /usr/sbin/nologin monitor
USER monitor

ENTRYPOINT ["python", "engine.py"]
CMD ["/data/pcaps/mixed.pcap", "--pretty"]
