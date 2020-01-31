/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

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
	TLSCertFile                    = "cert.pem"
	JWTCertsCacheTime              = "1m"
	TLSKeyFile                     = "key.pem"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	RootCADirPath                  = ConfigDir + "certs/cms-root-ca/"
	PIDFile                        = "sgx-host-verification-service.pid"
	ServiceRemoveCmd               = "systemctl disable sgx-host-verification-service"
	HashingAlgorithm               = crypto.SHA384
	PasswordRandomLength           = 20
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	DefaultDBRotationMaxRowCnt     = 100000
	DefaultDBRotationMaxTableCnt   = 10
	DefaultSSLCertFilePath         = ConfigDir + "sgx-host-verification-service-dbcert.pem"
	ServiceName                    = "sgx-host-verification-service"
	DefaultHttpPort                = 13000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultSHVSTlsSan              = "127.0.0.1,localhost"
	DefaultSHVSTlsCn               = "SGX HVS TLS Certificate"
	DefaultSHVSCertOrganization    = "INTEL"
	DefaultSHVSCertCountry         = "US"
	DefaultSHVSCertProvince        = "SF"
	DefaultSHVSCertLocality        = "SC"
	DefaultSHVSSchedulerTimer      = 60
	DefaultJwtValidateCacheKeyMins = 60
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
	HostStatusAgentConnFailure     = "AGENT-CONNECTION-FAILURE"
	HostStatusSCSConnFailure       = "SCS-CONNECTION-FAILURE"
	HostStatusProcessError         = "PROCESSING-ERROR"
	HostStatusUnknown              = "UNKNOWN"
	HostStatusConnected            = "CONNECTED"
	HostStatusRemoved              = "REMOVED"
	HostStatusUnsupportedSGX       = "UNSUPPORTED_SGX"
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
