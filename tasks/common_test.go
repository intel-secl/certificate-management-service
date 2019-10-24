/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
        "os"
	"intel/isecl/cms/constants"
)

func CreateSerialNumberFileAndJWTDir(){
        log.Trace("tasks/common_test:CreateSerialNumberFileAndJWTDir() Entering")
	defer log.Trace("tasks/common_test:CreateSerialNumberFileAndJWTDir() Leaving")

        os.MkdirAll(constants.ConfigDir, os.ModePerm)
        os.MkdirAll(constants.TrustedJWTSigningCertsDir, os.ModePerm)
        os.MkdirAll(constants.RootCADirPath, os.ModePerm)
        os.MkdirAll(constants.IntermediataCADirPath, os.ModePerm)
        var file, _ = os.Create(constants.SerialNumberPath)
        defer file.Close()
}

