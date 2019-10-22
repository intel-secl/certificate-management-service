/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"encoding/json"
	"net/http"
	"math/big"
	"io/ioutil"
	"os"
	"intel/isecl/cms/constants"
	"strings"
	"github.com/pkg/errors"
)

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func GetNextSerialNumber() (*big.Int, error) {
	serialNumberNew, err := ReadSerialNumber()
	if err != nil && strings.Contains(err.Error(),"no such file") {
		serialNumberNew = big.NewInt(0)
		err = WriteSerialNumber(serialNumberNew)
		return serialNumberNew, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
	} else if err != nil {
		return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot read from Serial Number file")
	} else {	
		serialNumberNew = serialNumberNew.Add(serialNumberNew, big.NewInt(1))
		err = WriteSerialNumber(serialNumberNew)
		if err != nil {
			return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
		}
		return serialNumberNew, nil
	}	
}

func ReadSerialNumber() (*big.Int, error) {	
	sn, err := ioutil.ReadFile(constants.SerialNumberPath)
	if err != nil {
		return nil, errors.Wrap(err, "utils/utils:ReadSerialNumber() Could not read serial number")
	} else {	
		var serialNumber = big.NewInt(0)
		serialNumber.SetBytes(sn)
		return serialNumber, nil
	}
}

func WriteSerialNumber(serialNumber *big.Int) error {	
	err := ioutil.WriteFile(constants.SerialNumberPath, serialNumber.Bytes(), 0660)
	os.Chmod(constants.SerialNumberPath, 0660)
	if err != nil {
		return errors.Wrap(err, "utils/utils:WriteSerialNumber() Failed to write serial-number to file")		
	}
	return nil
}
