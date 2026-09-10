FROM routeharbor-path-lab:local
RUN apt-get update && apt-get install -y --no-install-recommends age && rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 37071 routeharbor && useradd --uid 37071 --gid 37071 --no-create-home --home-dir /etc/routeharbor --shell /usr/sbin/nologin routeharbor
COPY routeharbor /usr/bin/routeharbor
COPY test.py /lab/admin-test.py
RUN chmod 0755 /usr/bin/routeharbor
ENTRYPOINT ["python3", "/lab/admin-test.py"]
