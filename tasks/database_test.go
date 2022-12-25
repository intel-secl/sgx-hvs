/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/shvs/v5/config"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseSetup(t *testing.T) {
	db_user := RandStringBytes()
	db_pass := RandStringBytes()
	testAssert := assert.New(t)
	c := config.Configuration{}
	s := Database{
		Flags:         []string{"-db-host=hostname", "-db-port=5432", "-db-user=" + db_user, "-db-pass=" + db_pass, "-db-name=scs_db"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	testAssert.Error(err)
	testAssert.Equal("hostname", c.Postgres.Hostname)
	testAssert.Equal(5432, c.Postgres.Port)
	testAssert.Equal(db_user, c.Postgres.Username)
	testAssert.Equal(db_pass, c.Postgres.Password)
	testAssert.Equal("scs_db", c.Postgres.DBName)
}

func TestDatabaseSetupEnv(t *testing.T) {
	db_user := RandStringBytes()
	db_pass := RandStringBytes()
	testAssert := assert.New(t)
	os.Setenv("SHVS_DB_HOSTNAME", "hostname")
	os.Setenv("SHVS_DB_PORT", "5432")
	os.Setenv("SHVS_DB_USERNAME", db_user)
	os.Setenv("SHVS_DB_PASSWORD", db_pass)
	os.Setenv("SHVS_DB_NAME", "scs_db")
	c := config.Configuration{}
	s := Database{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	testAssert.Error(err)
	testAssert.Equal("hostname", c.Postgres.Hostname)
	testAssert.Equal(5432, c.Postgres.Port)
	testAssert.Equal(db_user, c.Postgres.Username)
	testAssert.Equal(db_pass, c.Postgres.Password)
	testAssert.Equal("scs_db", c.Postgres.DBName)

	// Negative test - Invalid HOSTNAME
	os.Setenv("SHVS_DB_HOSTNAME", "Vf4zHSLdTG4N0vvgMxW3jmyCdykOq5AjgpLOFw48yf923GFD3pXuMP2zZipgWy8DSKmBClzP3mKkVvDa1ew0KqLTGIAHNswh6VLf8obeBSZ9HMW9gmIIFOHNYWAEqSlXZl87fum3PWnzfwp2ZMM3u1BJfHbj18cClEzSxF0wUz4EE3dfO48le7f7jmLcimuPJMy8QQPbSH6N9ZaUPgF6wVkOyK9Hs3qwWjPwkG6eHTp74b19lpKMJo16HScFpYhapSXH466ldmGyKT")
	os.Setenv("SHVS_DB_PORT", "5432")
	os.Setenv("SHVS_DB_USERNAME", RandStringBytes())
	os.Setenv("SHVS_DB_PASSWORD", RandStringBytes())
	os.Setenv("SHVS_DB_NAME", "scs_db")
	err = s.Run(ctx)
	testAssert.Error(err)

	// Negative test - Invalid USERNAME and PASSWORD
	os.Setenv("SHVS_DB_HOSTNAME", "hostname")
	os.Setenv("SHVS_DB_PORT", "5432")
	os.Setenv("SHVS_DB_USERNAME", RandStringBytes())
	os.Setenv("SHVS_DB_PASSWORD", "")
	os.Setenv("SHVS_DB_NAME", "scs_db")
	err = s.Run(ctx)
	testAssert.Error(err)

	// Negative test - empty SHVS_DB_NAME
	os.Setenv("SHVS_DB_HOSTNAME", "hostname")
	os.Setenv("SHVS_DB_PORT", "5432")
	os.Setenv("SHVS_DB_USERNAME", RandStringBytes())
	os.Setenv("SHVS_DB_PASSWORD", RandStringBytes())
	os.Setenv("SHVS_DB_NAME", "")
	err = s.Run(ctx)
	testAssert.Error(err)

}

func TestValidate(t *testing.T) {

	db := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "",
			},
		},
	}
	var ctx setup.Context
	err := db.Validate(ctx)
	assert.NotEmpty(t, err)

	db1 := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "test",
				Port:     0,
			},
		},
	}
	err = db1.Validate(ctx)
	assert.NotEmpty(t, err)

	db2 := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "test",
				Port:     1234,
				Username: "",
			},
		},
	}
	err = db2.Validate(ctx)
	assert.NotEmpty(t, err)

	db3 := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "test",
				Port:     1234,
				Username: RandStringBytes(),
				Password: "",
			},
		},
	}
	err = db3.Validate(ctx)
	assert.NotEmpty(t, err)

	db4 := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "test",
				Port:     1234,
				Username: RandStringBytes(),
				Password: RandStringBytes(),
				DBName:   "",
			},
		},
	}
	err = db4.Validate(ctx)
	assert.NotEmpty(t, err)

	db5 := Database{
		Config: &config.Configuration{
			Postgres: struct {
				DBName   string
				Username string
				Password string
				Hostname string
				Port     int
				SSLMode  string
				SSLCert  string
			}{
				Hostname: "test",
				Port:     1234,
				Username: RandStringBytes(),
				Password: RandStringBytes(),
				DBName:   "testdb",
			},
		},
	}
	err = db5.Validate(ctx)
	assert.Empty(t, err)
}

func createTestCertificate() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	// save private key
	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	}

	privateKeyFile, err := os.OpenFile("test.key", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := privateKeyFile.Close()
		if derr != nil {
			fmt.Fprintf(os.Stderr, "Error while closing file"+derr.Error())
		}
	}()
	err = pem.Encode(privateKeyFile, privateKey)
	if err != nil {
		log.Fatalf("I/O error while encoding private key file %v", err)
	}

	// save certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}
	caPEMFile, err := os.OpenFile("test.pem", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := caPEMFile.Close()
		if derr != nil {
			log.Fatalf("Error while closing file" + derr.Error())
		}
	}()
	err = pem.Encode(caPEMFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		log.Fatalf("Failed to Encode Certificate %v", err)
	}
}

func TestConfigureDBSSLParams(t *testing.T) {
	os.Mkdir("../test", 0667)
	createTestCertificate()
	type args struct {
		sslMode    string
		sslCertSrc string
		sslCert    string
	}
	tests := []struct {
		name     string
		args     args
		wantMode string
		wantCert string
		wantErr  bool
	}{
		{
			name: "Test with empty SSLCertSrc and invalid ssl cert path",
			args: args{
				sslMode:    "default",
				sslCertSrc: "",
				sslCert:    "/invalid/path",
			},
			wantErr: true,
		},
		{
			name: "Test with empty SSLCertSrc and ssl cert path",
			args: args{
				sslMode:    "default",
				sslCertSrc: "",
				sslCert:    "",
			},
			wantErr: true,
		},
		{
			name: "Test with empty SSLCertSrc and ssl cert path",
			args: args{
				sslMode:    "default",
				sslCertSrc: "invalid/path",
				sslCert:    "",
			},
			wantErr: true,
		},
		{
			name: "Test with allow mode",
			args: args{
				sslMode:    "allow",
				sslCertSrc: "invalid/path",
				sslCert:    "",
			},
			wantErr: false,
		},
		{
			name: "Test with verify-ca mode with test certs",
			args: args{
				sslMode:    "verify-ca",
				sslCertSrc: "test.pem",
				sslCert:    "../test/test.pem",
			},
			wantErr: false,
		},
		{
			name: "Test with verify-ca mode with empty sslCertSrc",
			args: args{
				sslMode:    "verify-ca",
				sslCertSrc: "",
				sslCert:    "test.pem",
			},
			wantErr: false,
		},
		{
			name: "Test with verify-ca mode with empty sslCert, default destination location doesn't exist",
			args: args{
				sslMode:    "verify-ca",
				sslCertSrc: "test.pem",
				sslCert:    "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := configureDBSSLParams(tt.args.sslMode, tt.args.sslCertSrc, tt.args.sslCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("configureDBSSLParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	os.Remove("test.key")
	os.Remove("test.pem")
	os.Remove("../test/test.pem")
	os.Remove("../test")
}
