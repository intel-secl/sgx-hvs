/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package docs

import (
	"intel/isecl/shvs/v3/resource"
)

// HostStatusResponse response payload
// swagger:response HostStatusResponse
type SwaggHostStatusResponse struct {
	// in:body
	Body resource.HostStatusResponse
}

// swagger:operation GET /host-status HostStatus hostStateInformation
// ---
// description: |
//   Retrieves the host status of the host based on the provided filter criteria from the SHVS database.
//   A valid bearer token is required to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: hostId
//   description: Unique ID of the host
//   in: query
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the host status.
//     schema:
//       "$ref": "#/definitions/HostStatusResponse"
//
// x-sample-call-endpoint: https://sgx-hvs.com:13000/sgx-hvs/v1/host-status?hostId=58cee2f3-d694-48ba-b8d2-e541544f5e22
// x-sample-call-output: |
//  [
//      {
//          "host_id": "58cee2f3-d694-48ba-b8d2-e541544f5e22",
//          "host_status": "CONNECTED",
//          "agent_retry_count": 0,
//          "scs_retry_count": 0,
//          "tcb_scs_retry_count": 0
//      }
//  ]
// ---
