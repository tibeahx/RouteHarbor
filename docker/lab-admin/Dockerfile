FROM openrhp-path-lab:local
RUN apt-get update && apt-get install -y --no-install-recommends age && rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 37071 openrhp && useradd --uid 37071 --gid 37071 --no-create-home --home-dir /etc/openrhp --shell /usr/sbin/nologin openrhp
COPY openrhp /usr/bin/openrhp
COPY test.py /lab/admin-test.py
RUN chmod 0755 /usr/bin/openrhp
ENTRYPOINT ["python3", "/lab/admin-test.py"]
