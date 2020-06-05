package com.optiv.appsec.checkpassword.exception;

public enum CheckPasswordErrorCode {
	BadConfiguration, //Something needs to be fixed on our end (TLS/SHA support, bad URL, etc.)
	APICallFailure    //Something is (probably) wrong with the API (Responses in wrong form, unable to read reply)
}
