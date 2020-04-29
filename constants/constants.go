/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	"time"
)

const (
	HomeDir                        = "/opt/sgx-host-verification-service/"
	ConfigDir                      = "/etc/sgx-host-verification-service/"
	ExecutableDir                  = "/opt/sgx-host-verification-service/bin/"
	ExecLinkPath                   = "/usr/bin/sgx-host-verification-service"
	RunDirPath                     = "/run/sgx-host-verification-service"
	LogDir                         = "/var/log/sgx-host-verification-service/"
	LogFile                        = LogDir + "sgx-host-verification-service.log"
	SecurityLogFile                = LogDir + "sgx-host-verification-service-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd               = "systemctl disable sgx-host-verification-service"
	HashingAlgorithm               = crypto.SHA384
	JWTCertsCacheTime              = "60m"
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	DefaultDBRotationMaxRowCnt     = 100000
	DefaultDBRotationMaxTableCnt   = 10
	DefaultSSLCertFilePath         = ConfigDir + "sgx-host-verification-service-dbcert.pem"
	ServiceName                    = "sgx-host-verification-service"
	SHVSUserName                   = "shvs"
	DefaultHttpPort                = 13000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSHVSTlsSan              = "127.0.0.1,localhost"
	DefaultSHVSTlsCn               = "SGX HVS TLS Certificate"
	DefaultSHVSSchedulerTimer      = 60
	DefaultSHVSAutoRefreshTimer    = 120
	DefaultSHVSHostInfoExpiryTime  = 240
	DefaultJwtValidateCacheKeyMins = 60
	CmsTlsCertDigestEnv            = "CMS_TLS_CERT_SHA384"
	SHVS_USER                      = "SHVS_ADMIN_USERNAME"
	SHVS_PASSWORD                  = "SHVS_ADMIN_PASSWORD"
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
	HostStatusUnknown              = "UNKNOWN"
	HostStatusConnected            = "CONNECTED"
	HostStatusRemoved              = "REMOVED"
	MaxRetryConnection             = 5
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
