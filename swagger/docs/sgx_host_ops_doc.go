/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package docs

import (
	"intel/isecl/shvs/v5/resource"
	"intel/isecl/shvs/v5/types"
	"time"
)

// SGXHostInfo response payload
// swagger:response SGXHostInfo
type RegisterHostInfoResponse struct {
	// in:body
	Body resource.SGXHostInfo
}

// ResponseJSON response payload
// swagger:response ResponseJSON
type JSONResponse struct {
	// in:body
	Body resource.ResponseJSON
}

// Hosts response payload
// swagger:response Hosts
type SwaggHostsInfo struct {
	// in:body
	Body types.Hosts
}

// HostInfo response payload
// swagger:response HostInfo
type HostInfo struct {
	// in:body
	Body types.HostInfo
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
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v2/platform-data?HostName=kbshostname
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
//   Agent pushes the platform enablement info and TCB status to SHVS at regular Interval
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
//     "$ref": "#/definitions/SGXHostInfo"
// responses:
//   '201':
//      description: Successfully registered the host.
//      schema:
//        "$ref": "#/definitions/ResponseJSON"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v2/hosts
// x-sample-call-input: |
//  {
//      "host_name": "kbshostname",
//      "description": "Rhel test host",
//      "uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//      "sgx_supported": true,
//      "flc_enabled": true,
//      "epc_offset": "0x40000000",
//      "epc_size": "3.0 GB",
//      "tcb_upToDate": true
//  }
// x-sample-call-output: |
//  {
//      "Id": "d60c9d18-a272-49b9-bf45-872f28407775",
//      "Status": "Created",
//      "Message": "SGX Host Data Created Successfully"
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
// - name: getPlatformData
//   description: Add platform data to the host info.
//   in: query
//   type: boolean
// - name: getStatus
//   description: Add host status to the host info.
//   in: query
//   type: boolean
// responses:
//   '200':
//     description: Successfully retrieved the hosts.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/Hosts"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v2/hosts?HostName=kbshostname
// x-sample-call-output: |
//  [
//    {
//        "host_ID": "d60c9d18-a272-49b9-bf45-872f28407775",
//        "host_name": "kbshostname",
//        "uuid": "88888888-8887-1214-0516-3707a5a5a5a5"
//    }
//  ]
// ---

// swagger:operation DELETE /hosts/{id} Host deleteHost
// ---
// description: |
//   Deletes a host associated with the specified host id from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//   Once done, Please make sure to uninstall the SGX Agent running on the corresponding host.
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
//    https://sgx-hvs.com:13000/sgx-hvs/v2/hosts/d60c9d18-a272-49b9-bf45-872f28407775
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
// - name: getPlatformData
//   description: Add platform data to the host info.
//   in: query
//   type: boolean
// - name: getStatus
//   description: Add host status to the host info.
//   in: query
//   type: boolean
// responses:
//   '200':
//     description: Successfully retrieved the host associated with the specified host id.
//     schema:
//       "$ref": "#/definitions/HostInfo"
//
// x-sample-call-endpoint: |
//    https://sgx-hvs.com:13000/sgx-hvs/v2/hosts/d60c9d18-a272-49b9-bf45-872f28407775
// x-sample-call-output: |
//  {
//    "host_ID": "d60c9d18-a272-49b9-bf45-872f28407775",
//    "host_name": "kbshostname",
//    "description": "",
//    "uuid": "88888888-8887-1214-0516-3707a5a5a5a5",
//  }
// ---
