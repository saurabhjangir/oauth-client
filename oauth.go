package oauth_client

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/saurabhjangir/utils-lib-golang/errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"

)

var (
	restClient = rest.RequestBuilder{
		BaseURL: "http://127.0.0.1:3301",
		Timeout: 100 * time.Millisecond,
	}
)

type accessToken struct {
	Token    string `json:"access_token"`
	ClientID int64  `json:"client_id"`
	UserID   int64  `json:"user_id"`
	Expires  int64  `json:"expires"`
}

type IoauthClient interface {
	AuthenticateRequest(*http.Request) *errors.RestErr
	GetClientID(*http.Request) (*int64, *errors.RestErr)
	GetCallerID(*http.Request) (*int64, *errors.RestErr)
	IsPublic(*http.Request) bool
}

type OauthClient struct{}

func (c *OauthClient) GetClientID(r *http.Request) (*int64, *errors.RestErr) {
	clientID, err := strconv.ParseInt(r.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return nil, errors.NewRestErrBadRequest(err.Error())
	}
	return &clientID, nil
}

func (c *OauthClient) GetCallerID(r *http.Request) (*int64, *errors.RestErr) {
	callerId, err := strconv.ParseInt(r.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return nil, errors.NewRestErrBadRequest(err.Error())
	}
	return &callerId, nil
}

func (c *OauthClient) IsPublic(r *http.Request) bool {
	if r == nil {
		return true
	}
	return r.Header.Get(headerXPublic) == "true"
}

func (c *OauthClient) AuthenticateRequest(r *http.Request) *errors.RestErr {
	if r == nil {
		return nil
	}
	cleanRequest(r)
	var at accessToken
	resp := restClient.Get(fmt.Sprintf("/oauth/access_token/%s",strings.TrimSpace(r.URL.Query().Get(paramAccessToken))))
	if resp == nil || resp.Response == nil {
		return errors.NewRestErrBadRequest("Error connecting to oauth service")
	}
	if resp.StatusCode > 299 {
		var err errors.RestErr
		marshErr := json.Unmarshal(resp.Bytes(), &err)
		if marshErr != nil {
			return &err
		}
		return &err
	}
	marshErr := json.Unmarshal(resp.Bytes(), &at)
	if marshErr != nil {
		return errors.NewRestErrBadRequest("Error processing oauth response")
	}
	r.Header.Set(headerXClientId, fmt.Sprintf("%s", at.ClientID))
	r.Header.Set(headerXCallerId, fmt.Sprintf("%s", at.UserID))
	return nil
}

func cleanRequest(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(headerXClientId)
	r.Header.Del(headerXClientId)
}
