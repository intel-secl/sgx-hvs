/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"intel/isecl/lib/common/v2/middleware"
	"intel/isecl/sgx-host-verification-service/config"
	"intel/isecl/sgx-host-verification-service/constants"
	"intel/isecl/sgx-host-verification-service/repository"
	"intel/isecl/sgx-host-verification-service/repository/postgres"
	"intel/isecl/sgx-host-verification-service/resource"
	"intel/isecl/sgx-host-verification-service/resource/scheduler"
	"intel/isecl/sgx-host-verification-service/tasks"
	"intel/isecl/sgx-host-verification-service/version"

	"intel/isecl/lib/common/v2/crypt"
	e "intel/isecl/lib/common/v2/exec"
	commLog "intel/isecl/lib/common/v2/log"
	commLogMsg "intel/isecl/lib/common/v2/log/message"
	commLogInt "intel/isecl/lib/common/v2/log/setup"
	cos "intel/isecl/lib/common/v2/os"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/lib/common/v2/validation"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	// Import driver for GORM
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
	SecLogWriter   io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sgx-host-verification-service <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    help|-h|-help    Show this help message")
	fmt.Fprintln(w, "    setup [task]     Run setup task")
	fmt.Fprintln(w, "    start            Start sgx-host-verification-service")
	fmt.Fprintln(w, "    status           Show the status of sgx-host-verification-service")
	fmt.Fprintln(w, "    stop             Stop sgx-host-verification-service")
	fmt.Fprintln(w, "    tlscertsha384    Show the SHA384 of the certificate used for TLS")
	fmt.Fprintln(w, "    uninstall        Uninstall sgx-host-verification-service")
	fmt.Fprintln(w, "    version          Show the version of sgx-host-verification-service")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Available Tasks for setup:")
	fmt.Fprintln(w, "    all                       Runs all setup tasks")
	fmt.Fprintln(w, "                              Required env variables:")
	fmt.Fprintln(w, "                                  - get required env variables from all the setup tasks")
	fmt.Fprintln(w, "                              Optional env variables:")
	fmt.Fprintln(w, "                                  - get optional env variables from all the setup tasks")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sgx-host-verification-service setup database [-force] [--arguments=<argument_value>]")
	fmt.Fprintln(w, "        - Avaliable arguments are:")
	fmt.Fprintln(w, "            - db-host    alternatively, set environment variable SHVS_DB_HOSTNAME")
	fmt.Fprintln(w, "            - db-port    alternatively, set environment variable SHVS_DB_PORT")
	fmt.Fprintln(w, "            - db-user    alternatively, set environment variable SHVS_DB_USERNAME")
	fmt.Fprintln(w, "            - db-pass    alternatively, set environment variable SHVS_DB_PASSWORD")
	fmt.Fprintln(w, "            - db-name    alternatively, set environment variable SHVS_DB_NAME")
	fmt.Fprintln(w, "            - db-sslmode <disable|allow|prefer|require|verify-ca|verify-full>")
	fmt.Fprintln(w, "                         alternatively, set environment variable SHVS_DB_SSLMODE")
	fmt.Fprintln(w, "            - db-sslcert path to where the certificate file of database. Only applicable")
	fmt.Fprintln(w, "                         for db-sslmode=<verify-ca|verify-full. If left empty, the cert")
	fmt.Fprintln(w, "                         will be copied to /etc/sgx-host-verification-service/tdcertdb.pem")
	fmt.Fprintln(w, "                         alternatively, set environment variable SHVS_DB_SSLCERT")
	fmt.Fprintln(w, "            - db-sslcertsrc <path to where the database ssl/tls certificate file>")
	fmt.Fprintln(w, "                         mandatory if db-sslcert does not already exist")
	fmt.Fprintln(w, "                         alternatively, set environment variable SHVS_DB_SSLCERTSRC")
	fmt.Fprintln(w, "        - Run this command with environment variable SHVS_DB_REPORT_MAX_ROWS and")
	fmt.Fprintln(w, "          SHVS_DB_REPORT_NUM_ROTATIONS can update db rotation arguments")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sgx-host-verification-service setup server [--port=<port>]")
	fmt.Fprintln(w, "        - Setup http server on <port>")
	fmt.Fprintln(w, "        - Environment variable SHVS_PORT=<port> can be set alternatively")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_ca_cert      Download CMS root CA certificate")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads new root CA cert")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>                                : for CMS API url")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>    : to ensure that SHVS is talking to the right CMS instance")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    download_cert TLS     Generates Key pair and CSR, gets it signed from CMS")
	fmt.Fprintln(w, "                          - Option [--force] overwrites any existing files, and always downloads newly signed TLS cert")
	fmt.Fprintln(w, "                          Required env variable if SHVS_NOSETUP=true or variable not set in config.yml:")
	fmt.Fprintln(w, "                              - CMS_TLS_CERT_SHA384=<CMS TLS cert sha384 hash>      : to ensure that SHVS is talking to the right CMS instance")
	fmt.Fprintln(w, "                          Required env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - CMS_BASE_URL=<url>               : for CMS API url")
	fmt.Fprintln(w, "                              - BEARER_TOKEN=<token>             : for authenticating with CMS")
	fmt.Fprintln(w, "                              - SAN_LIST=<san>                   : list of hosts which needs access to service")
	fmt.Fprintln(w, "                          Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                              - KEY_PATH=<key_path>              : Path of file where TLS key needs to be stored")
	fmt.Fprintln(w, "                              - CERT_PATH=<cert_path>            : Path of file/directory where TLS certificate needs to be stored")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exec, err := os.Executable()
	if err != nil {
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

func (a *App) configureLogs(stdOut, logFile bool) {

	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter

	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.LogWriter)
		} else {
			ioWriterDefault = os.Stdout
		}
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.SecLogWriter)
	f := commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, &f, ioWriterSecurity, false)

	slog.Info(commLogMsg.LogInit)
	log.Info(commLogMsg.LogInit)
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		fmt.Fprintf(os.Stderr, "Unrecognized command: %s\n", args[1])
		os.Exit(1)
	case "list":
		if len(args) < 3 {
			a.printUsage()
			os.Exit(1)
		}
		return a.PrintDirFileContents(args[2])
	case "tlscertsha384":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		hash, err := crypt.GetCertHexSha384(config.Global().TLSCertFile)
		if err != nil {
			fmt.Println(err.Error())
			return errors.Wrap(err, "app:Run() Could not derive tls certificate digest")
		}
		fmt.Println(hash)
		return nil
	case "run":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting sgx-host-verification-service service")
		}
	case "-h", "--help":
		a.printUsage()
		return nil
	case "start":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.start()
	case "stop":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.stop()
	case "status":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		flag.CommandLine.Parse(args[2:])
		a.uninstall(purge)
		os.Exit(0)
	case "version":
		fmt.Fprintf(a.consoleWriter(), "SGX Host Verification Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
		return nil
	case "setup":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		var context setup.Context
		if len(args) <= 2 {
			a.printUsage()
			os.Exit(1)
		}

		if args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "database" &&
			args[2] != "server" &&
			args[2] != "all" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		err := validateSetupArgs(args[2], args[3:])
		if err != nil {
			return errors.Wrap(err, "app:Run() Invalid setup task arguments")
		}

		a.Config = config.Global()
		err = a.Config.SaveConfiguration(context)
		if err != nil {
			fmt.Println("Error saving configuration: " + err.Error())
			os.Exit(1)
		}

		task := strings.ToLower(args[2])
		flags := args[3:]
		if args[2] == "download_cert" && len(args) > 3 {
			flags = args[4:]
		}

		a.Config = config.Global()

		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
					Flags:                flags,
					CmsBaseURL:           a.Config.CMSBaseUrl,
					CaCertDirPath:        constants.TrustedCAsStoreDir,
					TrustedTlsCertDigest: a.Config.CmsTlsCertDigest,
					ConsoleWriter:        os.Stdout,
				},
				setup.Download_Cert{
					Flags:              flags,
					KeyFile:            a.Config.TLSKeyFile,
					CertFile:           a.Config.TLSCertFile,
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
					CmsBaseURL:         a.Config.CMSBaseUrl,
					Subject: pkix.Name{
						CommonName: a.Config.Subject.TLSCertCommonName,
					},
					SanList:       a.Config.CertSANList,
					CertType:      "TLS",
					CaCertsDir:    constants.TrustedCAsStoreDir,
					BearerToken:   "",
					ConsoleWriter: os.Stdout,
				},
				tasks.Database{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
				tasks.Server{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
			},
			AskInput: false,
		}

		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			log.WithError(err).Error("Error running setup")
			fmt.Fprintf(os.Stderr, "Error running setup: %s\n", err)
			return errors.Wrap(err, "app:Run() Error running setup")
		}

		shvsUser, err := user.Lookup(constants.SHVSUserName)
		if err != nil {
			return errors.Wrapf(err, "Could not find user '%s'", constants.SHVSUserName)
		}

		uid, err := strconv.Atoi(shvsUser.Uid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse shvs user uid '%s'", shvsUser.Uid)
		}

		gid, err := strconv.Atoi(shvsUser.Gid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse shvs user gid '%s'", shvsUser.Gid)
		}

		//Change the file ownership to shvs user

		err = cos.ChownR(constants.ConfigDir, uid, gid)
		if err != nil {
			return errors.Wrap(err, "Error while changing file ownership")
		}
		if task == "download_cert" {
			err = os.Chown(a.Config.TLSKeyFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Key file")
			}

			err = os.Chown(a.Config.TLSCertFile, uid, gid)
			if err != nil {
				return errors.Wrap(err, "Error while changing ownership of TLS Cert file")
			}
		}
	}
	return nil
}

func (a *App) startServer() error {
	log.Trace("app:startServer() Entering")
	defer log.Trace("app:startServer() Leaving")

	c := a.configuration()
	log.Info("Starting SHVS server")

	// verify the database connection. If this does not succeed then we want to exit right here
	// the Open method has a retry operation that takes a long time
	if err := postgres.VerifyConnection(c.Postgres.Hostname, c.Postgres.Port, c.Postgres.DBName,
		c.Postgres.Username, c.Postgres.Password, c.Postgres.SSLMode, c.Postgres.SSLCert); err != nil {
		return err
	}

	// Open database
	shvsDB, err := postgres.Open(c.Postgres.Hostname, c.Postgres.Port, c.Postgres.DBName,
		c.Postgres.Username, c.Postgres.Password, c.Postgres.SSLMode, c.Postgres.SSLCert)
	if err != nil {
		log.WithError(err).Error("failed to open Postgres database")
		return err
	}
	defer shvsDB.Close()
	log.Trace("Migrating Database")
	shvsDB.Migrate()

	// Create Router, set routes
	r := mux.NewRouter()
	r.SkipClean(true)

	sr := r.PathPrefix("/sgx-hvs/v1/").Subrouter()
	var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)
	sr.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, fnGetJwtCerts, cacheTime))
	func(setters ...func(*mux.Router, repository.SHVSDatabase)) {
		for _, setter := range setters {
			setter(sr, shvsDB)
		}
	}(resource.SGXHostRegisterOps)

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	scheduler.StartWorkqueueScheduler(c.SchedulerTimer + 60)
	scheduler.StartAutoRefreshSchedular(shvsDB, c.SHVSRefreshTimer)
	scheduler.StartSHVSScheduler(shvsDB, c.SchedulerTimer)

	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.ReadTimeout,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    c.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		tlsCert := config.Global().TLSCertFile
		tlsKey := config.Global().TLSKeyFile
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.WithError(err).Info("Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	slog.Info(commLogMsg.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	slog.Info(commLogMsg.ServiceStop)
	return nil
}

func (a *App) start() error {
	log.Trace("app:start() Entering")
	defer log.Trace("app:start() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sgx-host-verification-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "sgx-host-verification-service"}, os.Environ())
}

func (a *App) stop() error {
	log.Trace("app:stop() Entering")
	defer log.Trace("app:stop() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sgx-host-verification-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "sgx-host-verification-service"}, os.Environ())
}

func (a *App) status() error {
	log.Trace("app:status() Entering")
	defer log.Trace("app:status() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sgx-host-verification-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "sgx-host-verification-service"}, os.Environ())
}

func (a *App) uninstall(purge bool) {
	log.Trace("app:uninstall() Entering")
	defer log.Trace("app:uninstall() Leaving")

	fmt.Println("Uninstalling SGX Host Verification Service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		log.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			log.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		log.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		log.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "SGX Host Verification uninstalled")
	a.stop()
}

func removeService() {
	log.Trace("app:removeService() Entering")
	defer log.Trace("app:removeService() Leaving")

	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove SGX Host Verification Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {
	log.Trace("app:validateCmdAndEnv() Entering")
	defer log.Trace("app:validateCmdAndEnv() Leaving")

	env_names := make([]string, 0)
	for k, _ := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, valid_err := validation.ValidateEnvList(env_names)
	if valid_err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.New("Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {
	log.Trace("app:validateSetupArgs() Entering")
	defer log.Trace("app:validateSetupArgs() Leaving")

	var fs *flag.FlagSet

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
		return nil

	case "database":
		env_names_cmd_opts := map[string]string{
			"SHVS_DB_HOSTNAME":   "db-host",
			"SHVS_DB_PORT":       "db-port",
			"SHVS_DB_USERNAME":   "db-user",
			"SHVS_DB_PASSWORD":   "db-pass",
			"SHVS_DB_NAME":       "db-name",
			"SHVS_DB_SSLMODE":    "db-sslmode",
			"SHVS_DB_SSLCERT":    "db-sslcert",
			"SHVS_DB_SSLCERTSRC": "db-sslcertsrc",
		}

		fs = flag.NewFlagSet("database", flag.ContinueOnError)
		fs.String("db-host", "", "Database Hostname")
		fs.Int("db-port", 0, "Database Port")
		fs.String("db-user", "", "Database Username")
		fs.String("db-pass", "", "Database Password")
		fs.String("db-name", "", "Database Name")
		fs.String("db-sslmode", "", "Database SSL Mode")
		fs.String("db-sslcert", "", "Database SSL Cert Destination")
		fs.String("db-sslcertsrc", "", "Database SSL Cert Source File")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "server":
		// this has a default port value of 8443
		return nil

	case "all":
		if len(args) != 0 {
			return errors.New("app:validateCmdAndEnv() Please setup the arguments with env")
		}
	}
	return nil
}

func (a *App) PrintDirFileContents(dir string) error {
	log.Trace("app:PrintDirFileContents() Entering")
	defer log.Trace("app:PrintDirFileContents() Leaving")

	if dir == "" {
		return fmt.Errorf("PrintDirFileContents needs a directory path to look for files")
	}
	data, err := cos.GetDirFileContents(dir, "")
	if err != nil {
		return err
	}
	for i, fileData := range data {
		fmt.Println("File :", i)
		fmt.Printf("%s", fileData)
	}
	return nil
}

func (a *App) DatabaseFactory() (repository.SHVSDatabase, error) {
	log.Trace("app:DatabaseFactory() Entering")
	defer log.Trace("app:DatabaseFactory() Leaving")

	pg := &a.configuration().Postgres
	p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
	if err != nil {
		fmt.Println("failed to open postgres connection for setup task")
		return nil, err
	}
	return p, nil
}

func fnGetJwtCerts() error {
	log.Trace("resource/service:fnGetJwtCerts() Entering")
	defer log.Trace("resource/service:fnGetJwtCerts() Leaving")

	conf := config.Global()

	if !strings.HasSuffix(conf.AuthServiceUrl, "/") {
		conf.AuthServiceUrl = conf.AuthServiceUrl + "/"
	}
	url := conf.AuthServiceUrl + "noauth/jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.TrustedCAsStoreDir, "*.pem")
	if err != nil {
		return errors.Wrap(err, "Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "Could not retrieve jwt certificate")
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "Could not store Certificate")
	}
	return nil
}
