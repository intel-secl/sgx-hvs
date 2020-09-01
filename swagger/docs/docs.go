// SGX-Host-Verification-Service
//
// SGX Host Verification Service (SHVS) retrieves platform-specific details from the registered SGX Agent
// and pushes the data to SGX Caching Service (SCS).
// SGX HVS also exposes API for SGX HUB to get platform-specific values.
// SGX HVS listening port is user-configurable.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 1.0
//  Host: sgx-hvs.com:13000
//  BasePath: /sgx-hvs/v1
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package docs
