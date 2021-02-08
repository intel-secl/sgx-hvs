FROM centos:8

#RUN useradd -u 1001 --comment "SGX Host Verification Service" --home /opt/shvs  --shell /bin/false shvs

COPY out/shvs /usr/bin/shvs

RUN mkdir -p /opt/shvs/dbscripts/

COPY out/installer/db_rotation.sql /opt/shvs/dbscripts/

#RUN chown shvs:shvs /opt/shvs/dbscripts/* 

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
