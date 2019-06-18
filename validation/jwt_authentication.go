/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"fmt"
	"intel/isecl/cms/utils"
	"net/http"

	//"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

/*
JWT claims struct
*/
type Token struct {
	GivenName string   `json:"GivenName"`
	Surname   string   `json:"SurName"`
	Email     string   `json:"Email"`
	Role      []string `json:"Role"`
	//UserId uint
	jwt.StandardClaims
}

// JwtAuthentication is used to validate the JWT provided for authentication along with the request
var JwtAuthentication = func(next http.Handler) http.Handler {

	return http.HandlerFunc(func(httpWriter http.ResponseWriter, httpRequest *http.Request) {

		response := make(map[string]interface{})
		tokenHeader := httpRequest.Header.Get("Authorization") //Grab the token from the header

		if tokenHeader == "" { //Token is missing, returns with error code 403 Unauthorized
			response = utils.Message(false, "Missing auth token")
			httpWriter.Header().Add("Content-Type", "application/json")
			httpWriter.WriteHeader(http.StatusUnauthorized)
			utils.Respond(httpWriter, response)
			return
		}

		splitToken := strings.Split(tokenHeader, " ") //The token normally comes in format `Bearer {token-body}`, check if the retrieved token matched this requirement
		if len(splitToken) != 2 {                     //If token is malformed, returns with error code 403 Unauthorized
			response = utils.Message(false, "Invalid/Malformed auth token")
			httpWriter.Header().Add("Content-Type", "application/json")
			httpWriter.WriteHeader(http.StatusUnauthorized)
			utils.Respond(httpWriter, response)
			return
		}

		tokenPart := splitToken[1] //Grab the token part
		tk := &Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte("qwertyuiopasdfghjklzxcvbnm123456"), nil
		})
		fmt.Println(tk.GivenName)
		fmt.Println(token.Claims)
		fmt.Println(token.Valid)

		if err != nil { //Malformed token, returns with http code 403
			response = utils.Message(false, "Malformed authentication token")
			httpWriter.Header().Add("Content-Type", "application/json")
			httpWriter.WriteHeader(http.StatusForbidden)
			utils.Respond(httpWriter, response)
			return
		}

		//Token validation is successful, move to the next request
		next.ServeHTTP(httpWriter, httpRequest)
	})
}
