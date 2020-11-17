/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package docs

import (
	"intel/isecl/shvs/v3/resource"
	"intel/isecl/shvs/v3/types"
	"time"
)

// RegisterHostInfo response payload
// swagger:response RegisterHostInfo
type RegisterHostInfoResponse struct {
	// in:body
	Body resource.RegisterHostInfo
}

// ResponseJson response payload
// swagger:response ResponseJson
type JsonResponse struct {
	// in:body
	Body resource.ResponseJson
}

// Hosts response payload
// swagger:response Hosts
type SwaggHostsInfo struct {
	// in:body
	Body types.Hosts
}

type NewHostSgxData struct {
	types.HostSgxData
	ExpiryTime time.Time `json:"validTo"`
}

type NewHostsSgxData []NewHostSgxData

// NewHostsSgxData response payload
// swagger:response NewHostsSgxData
type SwaggNewHostsSgxDataInfo struct {
	// in:body
	Body NewHostsSgxData
}

// swagger:operation GET /platform-data PlatformData getPlatformData
// ---
// description: |
//   Retrieves the platform data of the host based on the provided filter criteria from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: HostName
//   description: Name of the host.
//   in: query
//   type: string
// - name: numberOfMinutes
//   description: Results returned will be restricted to between the current time and number of minutes prior.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the platform data.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/NewHostsSgxData"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v1/platform-data?HostName=kbshostname
// x-sample-call-output: |
//  [
//      {
//          "epc_size": "2.0 GB",
//          "flc_enabled": true,
//          "host_id": "77baebed-5c94-4872-8da9-a754c3c0f4a1",
//          "sgx_enabled": true,
//          "sgx_supported": true,
//          "tcb_upToDate": true,
//          "validTo": "2020-07-10T17:20:41Z"
//      }
//  ]
// ---

// swagger:operation POST /hosts Host registerHost
// ---
//
// description: |
//   Registers a new host in the SHVS database. SGX Agent sends the registration request to SHVS along
//   with the overwritten flag (In this release the overwrite flag is set to true) and registers the SGX agent’s information to DB.
//   If the host is already registered, SHVS will re-register the host if the overwrite flag is true.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/RegisterHostInfo"
// responses:
//   '201':
//      description: Successfully registered the host.
//      schema:
//        "$ref": "#/definitions/ResponseJson"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v1/hosts
// x-sample-call-input: |
//  {
//      "host_name": "kbshostname",
//      "connection_string": "https://127.0.0.1:11001/sgx_agent/v1/host",
//      "description": "Rhel test host",
//      "uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//      "overwrite": true
//  }
// x-sample-call-output: |
//  {
//      "Id": "d60c9d18-a272-49b9-bf45-872f28407775",
//      "Status": "Created",
//      "Message": "SGX Host Registered Successfully"
//  }
// ---

// swagger:operation GET /hosts Host queryHosts
// ---
// description: |
//   Retrieves the list of hosts based on the provided filter criteria from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: HardwareUUID
//   description: Hardware UUID of the host.
//   in: query
//   type: string
//   format: uuid
// - name: HostName
//   description: Name of the host.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the hosts.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/Hosts"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v1/hosts?HostName=kbshostname
// x-sample-call-output: |
//  [
//    {
//        "host_ID": "d60c9d18-a272-49b9-bf45-872f28407775",
//        "host_name": "kbshostname",
//        "connection_string": "https://127.0.0.1:11001/sgx_agent/v1/host",
//        "uuid": "88888888-8887-1214-0516-3707a5a5a5a5"
//    }
//  ]
// ---

// swagger:operation DELETE /hosts/{id} Host deleteHost
// ---
// description: |
//   Deletes a host associated with the specified host id from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the host associated with the specified host id.
//
// x-sample-call-endpoint: |
//    https://sgx-hvs.com:13000/sgx-hvs/v1/hosts/d60c9d18-a272-49b9-bf45-872f28407775
// x-sample-call-output: |
//    204 No content
// ---

// swagger:operation GET /hosts/{id} Host getHosts
// ---
// description: |
//   Retrieves the host details associated with a specified host id from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: id
//   description: Unique ID of the host.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the host associated with the specified host id.
//     schema:
//       "$ref": "#/definitions/RegisterHostInfo"
//
// x-sample-call-endpoint: |
//    https://sgx-hvs.com:13000/sgx-hvs/v1/hosts/d60c9d18-a272-49b9-bf45-872f28407775
// x-sample-call-output: |
//  {
//    "host_ID": "d60c9d18-a272-49b9-bf45-872f28407775",
//    "host_name": "kbshostname",
//    "connection_string": "https://127.0.0.1:11001/sgx_agent/v1/host",
//    "description": "",
//    "uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//    "overwrite": false
//  }
// ---
