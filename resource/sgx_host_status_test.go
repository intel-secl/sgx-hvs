/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/lib/common/v5/context"
	"intel/isecl/lib/common/v5/types/aas"
	"intel/isecl/shvs/v5/repository/mock"
	"intel/isecl/shvs/v5/types"
	"net/http"
	"net/http/httptest"
	"time"

	"intel/isecl/shvs/v5/constants"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
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

	// To GetHostStateInformation
	Describe("GetHostStateInformation", func() {
		Context("Validate GetHostStateInformation request", func() {

			It("Should not get host state information - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status", nil)
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

			It("Should not get host state information - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get host state information - Insufficient roles were given", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status?hostIdInvalid=status", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get host state information - invalid UUID were given in request", func() {
				hostStatus := &types.HostStatus{
					ID:          uuid.MustParse("5a5def52-39b5-11ed-a261-0242ac120002"),
					HostID:      uuid.New(),
					Status:      "active",
					CreatedTime: time.Now(),
				}
				db.HostStatusRepository().Create(hostStatus)

				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status?hostId=5a5def52-39b5-11ed-a261-0242ac120002", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
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

			It("Should not get host state information - Invalid UUID were given in request URL", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status?hostId=invalidUUID", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should not get host state information - unknown UUID were given in request", func() {
				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status?hostId=822103f3-4281-46f6-bf15-4d359699faf3", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})

			It("Should get host state information - valid request were given", func() {
				hostStatus := &types.HostStatus{
					ID:          uuid.MustParse("86f46383-0d6d-40b2-80bd-dc35b933afb8"),
					HostID:      uuid.New(),
					Status:      "active",
					CreatedTime: time.Now(),
				}
				db.HostStatusRepository().Create(hostStatus)

				SGXHostRegisterOps(router, db)

				req, err := http.NewRequest(http.MethodGet, "/host-status?hostId=86f46383-0d6d-40b2-80bd-dc35b933afb8", nil)
				val := []aas.RoleInfo{
					{
						Service: constants.ServiceName,
						Name:    constants.HostDataReaderGroupName,
						Context: "type=SHVS",
					},
				}
				req = context.SetUserRoles(req, val)
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostDataReaderGroupName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

		})
	})
})
