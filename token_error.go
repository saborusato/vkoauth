package vkoauth

import (
	"fmt"
	"net/http"
)

type TokenErrorJson struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	RedirectURI      string `json:"redirect_uri"`
	ValidationType   string `json:"validation_type,omitempty"`
	ValidationSid    string `json:"validation_sid,omitempty"`
	PhoneMask        string `json:"phone_mask,omitempty"`
	ValidationResend string `json:"validation_resend,omitempty"`
	CaptchaSid       string `json:"captcha_sid,omitempty"`
	CaptchaImg       string `json:"captcha_img,omitempty"`
	ErrorType        string `json:"error_type,omitempty"`
}

type TokenError struct {
	Response         *http.Response
	Body             []byte
	description      string
	RedirectURI      string
	ErrorCode        string
	ErrorType        string
	ValidationType   string
	ValidationSid    string
	PhoneMask        string
	ValidationResend string
	CaptchaSid       string
	CaptchaImg       string
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("Get token error: %s %s", e.ErrorCode, e.description)
}
