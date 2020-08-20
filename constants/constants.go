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
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	DefaultSSLCertFilePath         = ConfigDir + "shvs-dbcert.pem"
	ServiceName                    = "SHVS"
	RegisterHostGroupName          = "HostRegistration"
	HostListReaderGroupName        = "HostsListReader"
	HostDataReaderGroupName        = "HostDataReader"
	HostListManagerGroupName       = "HostListManager"
	SHVSUserName                   = "shvs"
	ExpiryTimeKeyName              = "validTo"
	DefaultHttpsPort               = 13000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSHVSTlsSan              = "127.0.0.1,localhost"
	DefaultSHVSTlsCn               = "SHVS TLS Certificate"
	DefaultSHVSSchedulerTimer      = 60
	DefaultSHVSAutoRefreshTimer    = 120
	DefaultSHVSHostInfoExpiryTime  = 240
	DefaultJwtValidateCacheKeyMins = 60
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
	ConnectionString               = "connection-string"
	ID                             = "id"
	HostID                         = "host-id"
	HostStatus                     = "host-status"
	HostStatusAgentQueued          = "AGENT-QUEUE"
	HostStatusAgentRetry           = "AGENT-RETRY"
	HostStatusAgentProcessing      = "AGENT-PROCESSING"
	HostStatusSCSQueued            = "SCS-QUEUE"
	HostStatusSCSRetry             = "SCS-RETRY"
	HostStatusSCSProcessing        = "SCS-PROCESSING"
	HostStatusTCBSCSStatusQueued   = "TCBStatus-SCS-QUEUED"
	HostStatusSCSTCBProcessing     = "SCS_TCB-PROCESSING"
	HostStatusTCBSCSRetry          = "SCS_TCB-RETRY"
	HostStatusAgentConnFailure     = "AGENT-CONNECTION-FAILURE"
	HostStatusSCSConnFailure       = "SCS-CONNECTION-FAILURE"
	HostStatusTCBSCSConnFailure    = "TCBStatus-SCS-CONNECTION-FAILURE"
	HostStatusProcessError         = "PROCESSING-ERROR"
	HostStatusConnected            = "CONNECTED"
	HostStatusRemoved              = "REMOVED"
	MaxRetryConnection             = 5
)
