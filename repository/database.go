/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type SHVSDatabase interface {
	Migrate() error
	HostRepository() HostRepository
	HostStatusRepository() HostStatusRepository
	HostCredentialRepository() HostCredentialRepository
	HostReportRepository() HostReportRepository
	HostSgxDataRepository() HostSgxDataRepository
	PlatformTcbRepository() PlatformTcbRepository
	Close()
}
