/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
        "os"
)

func CreateSerialNumberFileAndJWTDir(){
        os.MkdirAll("/etc/cms", os.ModePerm)
        os.MkdirAll("/etc/cms/jwt", os.ModePerm)
        var file, _ = os.Create("/etc/cms/serial-number")
        defer file.Close()
}

