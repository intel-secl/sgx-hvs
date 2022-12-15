/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"intel/isecl/lib/common/v5/context"
	"intel/isecl/lib/common/v5/types/aas"
	"intel/isecl/shvs/v5/constants"
	"intel/isecl/shvs/v5/repository/mock"
	"intel/isecl/shvs/v5/types"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/jinzhu/gorm"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetHosts", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	hostRepo := mock.MockHostRepository{}
	hostStatusRepo := mock.MockHostStatusRepository{}
	hostSgxRepo := mock.MockHostSgxDataRepository{}

	db := mock.NewMockDatabase(hostRepo, hostStatusRepo, hostSgxRepo)

	thisHostStatus := types.HostStatus{
		ID:          uuid.New(),
		HostID:      uuid.New(),
		Status:      "Active",
		CreatedTime: time.Now(),
	}
	db.HostStatusRepository().Create(&thisHostStatus)

	thisHost := types.Host{
		ID:          uuid.New(),
		CreatedTime: time.Now(),
	}
	db.HostRepository().Create(&thisHost)

	BeforeEach(func() {
		router = mux.NewRouter()
	})

	// To test getHosts
	Describe("GetHosts", func() {
		Context("Validate GetHosts request", func() {
			It("Should not get hosts - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/hosts/{id}", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not get hosts - Insufficient permissions were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/hosts/{id}", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get hosts - Invalid host ID given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/hosts/db000616-25cb-4094-a2f1-8966f7f5d0fd", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})

			It("Should not get hosts - invalid query parameters given in URL", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts/%s?invalid=true", thisHost.ID.String())

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get hosts - invalid query parameters given in URL", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts/%s?getPlatformData=testData", thisHost.ID.String())

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get hosts - invalid query parameters given in URL", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts/%s?getStatus=testData", thisHost.ID.String())

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should get hosts - valid query parameters given", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts/%s?getStatus=true&getPlatformData=true", thisHost.ID.String())

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

			It("Should get hosts - valid host id given", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts/%s", thisHost.ID.String())

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})

	// Query Hosts.

	Describe("Query Hosts", func() {
		Context("Validate queryhosts /hosts request", func() {
			It("Should not perform queryhosts - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/hosts", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not return hosts - No data found", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/hosts", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})

			// Invalid query parameter given
			It("Should not perform queryhosts - should not return hostdata", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?getInvalidPlatformData=testData")
				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			// Invalid query parameter value given
			It("Should not perform queryhosts - should not return hostdata", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?HardwareUUID=testData")
				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			// Test with getPlatformData query parameter value given
			It("Should not perform queryhosts - should not return hostdata", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?getPlatformData=test")
				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			// Test with getPlatformData query parameter value given
			It("Should not perform queryhosts - should not return hostdata", func() {
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?getPlatformData=test")
				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not perform queryhosts - should not return hostdata invalid hostname given", func() {
				host := types.Host{
					ID:          uuid.New(),
					Name:        "testh_ostname",
					Description: "test description",
					CreatedTime: time.Now(),
					Deleted:     false,
				}
				createdHost, _ := db.HostRepository().Create(&host)
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?HostName=%s", createdHost.Name)
				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should perform queryhosts - should return hostdata", func() {
				host := types.Host{
					ID:          uuid.New(),
					Name:        "testhostname",
					Description: "test description",
					CreatedTime: time.Now(),
					Deleted:     false,
				}
				createdHost, _ := db.HostRepository().Create(&host)
				SGXHostRegisterOps(router, db)

				validPath := fmt.Sprintf("/hosts?HostName=%s", createdHost.Name)

				// validHWUUIDPath := fmt.Sprintf("/hosts?HostName=%s", createdHost.Name)

				req, err := http.NewRequest(http.MethodGet, validPath, nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		// DELETE hosts.
		Context("Validate delete hosts /hosts/{id} request", func() {
			It("Should not perform delete hosts - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodDelete, "/hosts/993118ef-a52d-4f27-b88f-28fb56cd4e8e", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not delete hosts - Invalid UUID given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodDelete, "/hosts/da31ea10937e1-11ed-a261-0242ac120002", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListManagerGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not return hosts - No data found", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodDelete, "/hosts/83492bfd-f7dd-4691-ab03-7d19cbd8813b", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListManagerGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListManagerGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				// Expect(w.Code).To(Equal(http.StatusNotFound))
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})

			It("Should delete host with specified UUID - Valid delete request given", func() {
				SGXHostRegisterOps(router, db)

				host := types.Host{
					ID:          uuid.New(),
					Name:        "testhostname",
					Description: "test description",
					CreatedTime: time.Now(),
					Deleted:     false,
				}
				createdHost, _ := db.HostRepository().Create(&host)

				hostStatus := types.HostStatus{
					ID:          host.ID,
					HostID:      uuid.New(),
					Status:      "active",
					CreatedTime: host.CreatedTime,
					UpdatedTime: host.UpdatedTime,
					ExpiryTime:  host.UpdatedTime,
				}
				db.HostStatusRepository().Create(&hostStatus)

				SGXHostRegisterOps(router, db)

				validHWUUIDPath := fmt.Sprintf("/hosts/%s", createdHost.ID)
				req, err := http.NewRequest(http.MethodDelete, validHWUUIDPath, nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostListManagerGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		// Register hosts.
		Context("Validate rgister hosts /hosts request", func() {
			It("Should not register hosts - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodPost, "/hosts", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostListReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not register host - Empty Body content given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodPost, "/hosts", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not register host - Invalid body content given", func() {
				SGXHostRegisterOps(router, db)

				requestBody := `{"host_name":"test_hostname","description":"host test","uuid":"b0fcfba4-c587-4417-ba3b-f92dbcc366f8","sgx_supported":true,"sgx_enabled":false,"flc_enabled":true,"epc_offset":"0x12345","epc_size":"0x12345","tcb_upToDate":false}"`
				req, err := http.NewRequest(http.MethodPost, "/hosts", strings.NewReader(requestBody))
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not register host - No content-type provided", func() {
				SGXHostRegisterOps(router, db)
				request := SGXHostInfo{
					HostName:     "test_hostname",
					Description:  "host test",
					UUID:         "b0fcfba4-c587-4417-ba3b-f92dbcc366f8",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
			// valid request.
			It("Should register host - valid request provided", func() {
				SGXHostRegisterOps(router, db)
				request := SGXHostInfo{
					HostName:     "validtesthostname",
					Description:  "host test",
					UUID:         "b0fcfba4-c587-4417-ba3b-f92dbcc366f8",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				req = context.SetTokenSubject(req, "b0fcfba4-c587-4417-ba3b-f92dbcc366f8")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})

			// Try to add existing host, so that we can validate error. @ RetrieveAnyIfExists
			It("Should not register host - Invalid request to fail at RetrieveAnyIfExists", func() {

				// Create host before register request.
				host := &types.Host{
					ID:           uuid.MustParse("b0fcfba4-c587-4417-ba3b-f92dbcc366f8"),
					Name:         "testHostNameInternalServerEror",
					Description:  "host test",
					HardwareUUID: uuid.New(),
					CreatedTime:  time.Now(),
					Deleted:      false,
				}
				db.HostRepository().Create(host)

				SGXHostRegisterOps(router, db)

				request := SGXHostInfo{
					HostName:     "testHostNameInternalServerEror",
					Description:  "host test",
					UUID:         "b0fcfba4-c587-4417-ba3b-f92dbcc366f8",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req = context.SetTokenSubject(req, "b0fcfba4-c587-4417-ba3b-f92dbcc366f8")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			// To reach pushSGXEnablementInfoToDB
			// Try to add existing host, so that we can validate error. @ RetrieveAnyIfExists
			It("Should not register host - Invalid request to fail at RetrieveAnyIfExists", func() {

				// Create host before register request.
				host := &types.Host{
					ID:           uuid.MustParse("a7e53599-84a9-4a39-868f-46ac9dd3c070"),
					Name:         "testHostNamePushSGX",
					Description:  "host test",
					HardwareUUID: uuid.MustParse("a7e53599-84a9-4a39-868f-46ac9dd3c070"),
					CreatedTime:  time.Now(),
					Deleted:      false,
				}
				db.HostRepository().Create(host)

				thisHostStatus := types.HostStatus{
					ID:          host.ID,
					HostID:      host.HardwareUUID,
					Status:      "Active",
					CreatedTime: host.CreatedTime,
				}
				db.HostStatusRepository().Create(&thisHostStatus)

				SGXHostRegisterOps(router, db)

				request := SGXHostInfo{
					HostName:     "testHostNamePushSGX",
					Description:  "host test",
					UUID:         "a7e53599-84a9-4a39-868f-46ac9dd3c070",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req = context.SetTokenSubject(req, "a7e53599-84a9-4a39-868f-46ac9dd3c070")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

			// Try to add existing host, so that we can validate error.With different context.
			It("Should not register host - Invalid request to fail at RetrieveAnyIfExists", func() {

				// Create host before register request.
				host := &types.Host{
					ID:           uuid.MustParse("fb15c087-9792-452d-86f1-ad54573810f2"),
					Name:         "testHostNameTest",
					Description:  "host test",
					HardwareUUID: uuid.MustParse("854bad10-0498-4f49-83e6-b630712a6e97"),
					CreatedTime:  time.Now(),
					Deleted:      false,
				}
				db.HostRepository().Create(host)

				SGXHostRegisterOps(router, db)

				request := SGXHostInfo{
					HostName:     "testHostNameTest",
					Description:  "host test",
					UUID:         "854bad10-0498-4f49-83e6-b630712a6e97",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req = context.SetTokenSubject(req, "854bad10-0498-4f49-83e6-b630712a6e97")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not register host - Invalid request to fail at RetrieveAnyIfExists", func() {
				SGXHostRegisterOps(router, db)
				request := SGXHostInfo{
					HostName:     "TEST-HOST-NAME",
					Description:  "host test",
					UUID:         "b0fcfba4-c587-4417-ba3b-f92dbcc366f8",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				req = context.SetTokenSubject(req, "b0fcfba4-c587-4417-ba3b-f92dbcc366f8")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not register host - invalid TOKEN subject provided", func() {
				SGXHostRegisterOps(router, db)
				request := SGXHostInfo{
					HostName:     "testhostname",
					Description:  "host test",
					UUID:         "b0fcfba4-c587-4417-ba3b-f92dbcc366f8",
					SgxSupported: true,
					SgxEnabled:   false,
					FlcEnabled:   true,
					EpcOffset:    "0x12345",
					EpcSize:      "0x12345",
					TcbUptodate:  false,
				}

				body, _ := json.Marshal(request)
				req, err := http.NewRequest(http.MethodPost, "/hosts", bytes.NewReader(body))

				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataUpdaterGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataUpdaterGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				req = context.SetTokenSubject(req, "invalid-token-subject")

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

		})
	})
})

func Test_errorHandlerFunc_ServeHTTP(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		ehf  errorHandlerFunc
		args args
	}{
		{
			name: "To validate resource error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return &resourceError{Message: "Resource Error", StatusCode: http.StatusConflict}
			},
		},
		{
			name: "To validate resource error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return resourceError{Message: "Resource Error", StatusCode: http.StatusConflict}
			},
		},
		{
			name: "To validate resource error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return privilegeError{Message: "Resource Error", StatusCode: http.StatusConflict}
			},
		},
		{
			name: "To validate privilege error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return &privilegeError{Message: "Invalid privilege Error", StatusCode: http.StatusUnauthorized}
			},
		},
		{
			name: "To validate Internal server error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return errors.New("internal server error")
			},
		},
		{
			name: "To validate not found error",
			args: args{
				w: &httptest.ResponseRecorder{},
				r: &http.Request{},
			},
			ehf: func(w http.ResponseWriter, r *http.Request) error {
				return gorm.ErrRecordNotFound
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ehf.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}
