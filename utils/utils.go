package utils

import (
	"encoding/json"
	"net/http"
	"math/big"
	"io/ioutil"
	"intel/isecl/cms/constants"
	log "github.com/sirupsen/logrus"
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
	if err != nil {		
		return nil, err
	} else {	
		serialNumberNew = serialNumberNew.Add(serialNumberNew, big.NewInt(1))
		err = WriteSerialNumber(serialNumberNew)
		if err != nil {
			log.Errorf("Cannot write to Serial Number file")
		}
		return serialNumberNew, nil
	}	
}

func ReadSerialNumber() (*big.Int, error) {	
	sn, err := ioutil.ReadFile(constants.CMS_SERIAL_NUMBER_FILE)
	if err != nil {
		log.Errorf("Cannot read from Serial Number file: %v", err)
		return nil, err
	} else {	
		var serialNumber = big.NewInt(0)
		serialNumber.SetBytes(sn)
		return serialNumber, nil
	}
}

func WriteSerialNumber(serialNumber *big.Int) error {	
    err := ioutil.WriteFile(constants.CMS_SERIAL_NUMBER_FILE, serialNumber.Bytes(), 0660)
	if err != nil {
		log.Errorf("Failed to write serial-number to file: %s", err)
		return err		
	}
	return nil
}