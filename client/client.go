/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package client

import (
	"net/http"
	"net/url"
)

// Client for consuming the TDService API
type Client struct {
	BaseURL string
	// Username used to authenticate with the KMS. Username is only used for obtaining an authorization token, which is automatically used for requests.
	Username string
	// Password to supply for the Username
	Password string
	// A reference to the underlying http Client.
	// If the value is nil, a default client will be created and used.
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{}
	}
	return c.HTTPClient
}

func (c *Client) resolvePath(path string) (string, error) {
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", err
	}
	rel := baseURL.ResolveReference(&url.URL{Path: path})
	return rel.String(), err
}

func (c *Client) dispatchRequest(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(c.Username, c.Password)
	return c.httpClient().Do(req)
}

