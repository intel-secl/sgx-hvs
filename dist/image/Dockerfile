# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

COPY out/shvs /usr/bin/shvs

RUN mkdir -p /opt/shvs/dbscripts/

COPY out/db_rotation.sql /opt/shvs/dbscripts/

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
