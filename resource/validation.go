/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/sgx-host-verification-service/constants"
	"regexp"
)

var regExMap = map[string]*regexp.Regexp{
	constants.HostName:         regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`),
	constants.ConnectionString: regexp.MustCompile(`^\S+$`),
	constants.Description:      regexp.MustCompile(`^[0-9a-zA-Z ]{0,31}$`),
	constants.ID:               regexp.MustCompile(`([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}){1}`),
	constants.HostID:           regexp.MustCompile(`([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}){1}`),
	constants.HostStatus:       regexp.MustCompile(`^[A-Za-z]*$`),
	constants.UUID:             regexp.MustCompile(`([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}){1}`)}

func ValidateInputString(key string, inString string) bool {

	regEx := regExMap[key]
	if len(key) <= 0 || !regEx.MatchString(inString) {
		log.WithField(key, inString).Error("Input Validation failing")
		return false
	}
	log.WithField(key, inString).Debug("Input Validation")
	return true
}
