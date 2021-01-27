// SGX-Host-Verification-Service
//
//Agent pushes the platform enablement info and TCB status to SHVS at regular Interval
// SGX HVS also exposes API for SGX HUB to get platform-specific values.
// SGX HVS listening port is user-configurable.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 1.0
//  Host: sgx-hvs.com:13000
//  BasePath: /sgx-hvs/v2
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
