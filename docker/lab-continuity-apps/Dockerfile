FROM openrhp-path-lab:local
# Test tooling only. The gateway and relay remain Go-standard-library programs.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client python3-venv python3-websockets && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv --system-site-packages /opt/continuity-test-env && /opt/continuity-test-env/bin/pip install --no-cache-dir --only-binary=:all: aioquic==1.2.0
ENV PATH="/opt/continuity-test-env/bin:${PATH}"
