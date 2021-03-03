/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"time"
)

const (
	HomeDir                        = "/opt/shvs/"
	ConfigDir                      = "/etc/shvs/"
	ExecLinkPath                   = "/usr/bin/shvs"
	RunDirPath                     = "/run/shvs"
	LogDir                         = "/var/log/shvs/"
	LogFile                        = LogDir + "shvs.log"
	SecurityLogFile                = LogDir + "shvs-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd               = "systemctl disable shvs"
	JWTCertsCacheTime              = "60m"
	DefaultSSLCertFilePath         = ConfigDir + "shvs-dbcert.pem"
	ServiceName                    = "SHVS"
	ExplicitServiceName            = "SGX Host Verification Service"
	HostDataUpdaterGroupName       = "HostDataUpdater"
	HostListReaderGroupName        = "HostsListReader"
	HostDataReaderGroupName        = "HostDataReader"
	HostListManagerGroupName       = "HostListManager"
	SHVSUserName                   = "shvs"
	ExpiryTimeKeyName              = "validTo"
	DefaultHTTPSPort               = 13000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSHVSTlsSan              = "127.0.0.1,localhost"
	DefaultSHVSTlsCn               = "SHVS TLS Certificate"
	DefaultSHVSSchedulerTimer      = 60
	DefaultSHVSAutoRefreshTimer    = 120
	DefaultSHVSHostInfoExpiryTime  = 4 * 60 * 60
	SHVSLogLevel                   = "SHVS_LOGLEVEL"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
	UUID                           = "uuid"
	Description                    = "description"
	HostName                       = "host-name"
	ID                             = "id"
	HostID                         = "host-id"
	HostStatus                     = "host-status"
	HostStatusInactive             = "IN-ACTIVE"
	HostStatusConnected            = "CONNECTED"
	HostStatusRemoved              = "REMOVED"
	MaxQueryParamsLength           = 50
)
