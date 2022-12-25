/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/lib/common/v5/context"
	"intel/isecl/lib/common/v5/types/aas"
	"intel/isecl/shvs/v5/repository/mock"
	"intel/isecl/shvs/v5/types"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"intel/isecl/shvs/v5/constants"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Platform Data", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	hostRepo := mock.MockHostRepository{}
	hostStatusRepo := mock.MockHostStatusRepository{}
	hostSgxRepo := mock.MockHostSgxDataRepository{}

	db := mock.NewMockDatabase(hostRepo, hostStatusRepo, hostSgxRepo)

	BeforeEach(func() {
		router = mux.NewRouter()
		SGXHostRegisterOps(router, db)
	})

	// platform-data related tests.

	Describe("Validate platform-data related tests", func() {
		Context("Validate /platform-data request", func() {
			It("Should not get platform-data - Insufficient roles were given", func() {

				req, err := http.NewRequest(http.MethodGet, "/platform-data", nil)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not get platform-data - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data", nil)
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
				Expect(w.Code).To(Equal(http.StatusForbidden))
			})

			It("Should get platform-data - Valid request with all required roles and permissions given", func() {

				hostSgxData := &types.HostSgxData{
					ID:           uuid.New(),
					HostID:       uuid.New(),
					SgxSupported: true,
					SgxEnabled:   true,
					FlcEnabled:   true,
					EpcAddr:      "0x12345",
					EpcSize:      "0x67890",
					TcbUptodate:  true,
					CreatedTime:  time.Now(),
				}
				db.HostSgxDataRepository().Create(hostSgxData)

				hostStatus := &types.HostStatus{
					ID:          hostSgxData.ID,
					HostID:      hostSgxData.HostID,
					Status:      "active",
					CreatedTime: hostSgxData.CreatedTime,
					ExpiryTime:  hostSgxData.CreatedTime.Add(1 * time.Hour),
				}
				db.HostStatusRepository().Create(hostStatus)

				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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

			It("Should not get platform-data - Invalid request with invalid query parameters", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data?InvalidQuery=test", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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

			It("Should not get platform-data - Invalid request with invalid query parameter value", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data?HostName=test_test", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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

			It("Should not get platform-data - Invalid request with unknown hostname", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data?HostName=unknownHostName", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			It("Should not get platform-data - multiple query parameters given in URL", func() {
				SGXHostRegisterOps(router, db)

				queryString := "?"
				for i := 0; i <= 60; i++ {
					queryString = queryString + "&test" + strconv.Itoa(i) + "=test" + strconv.Itoa(i)
				}
				queryString = strings.Replace(queryString, "&", "", 1)
				manyQPPath := fmt.Sprintf("/platform-data%s", queryString)

				req, err := http.NewRequest(http.MethodGet, manyQPPath, nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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

			It("Should not get platform-data - Invalid query parameter value for numberOfMinutes", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data?numberOfMinutes=unknownHostName", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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

			It("Should get platform-data - Valid request with all required roles and permissions given", func() {

				host := &types.Host{
					ID:           uuid.New(),
					Name:         "test",
					Description:  "test-host",
					HardwareUUID: uuid.New(),
					CreatedTime:  time.Now(),
					Deleted:      false,
				}
				db.HostRepository().Create(host)

				hostSgxData := &types.HostSgxData{
					ID:           host.ID,
					HostID:       host.ID,
					SgxSupported: true,
					SgxEnabled:   true,
					FlcEnabled:   true,
					EpcAddr:      "0x12345",
					EpcSize:      "0x67890",
					TcbUptodate:  true,
					CreatedTime:  time.Now(),
				}
				db.HostSgxDataRepository().Create(hostSgxData)

				hostStatus := &types.HostStatus{
					ID:          host.ID,
					HostID:      hostSgxData.HostID,
					Status:      "active",
					CreatedTime: hostSgxData.CreatedTime,
					ExpiryTime:  hostSgxData.CreatedTime.Add(1 * time.Hour),
				}
				db.HostStatusRepository().Create(hostStatus)

				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/platform-data?HostName=test", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
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
})
