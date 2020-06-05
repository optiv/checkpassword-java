package com.optiv.appsec.checkpassword.exception;

public class CheckPasswordException extends Exception {

	private static final long serialVersionUID = 1920827738045331037L;

	private final CheckPasswordErrorCode errorCode;
	
	public CheckPasswordException(CheckPasswordErrorCode errorCode) {
		super();
		this.errorCode = errorCode;
	}

	public CheckPasswordException(String message, CheckPasswordErrorCode errorCode) {
		super(message);
		this.errorCode = errorCode;
	}

	public CheckPasswordException(Throwable cause, CheckPasswordErrorCode errorCode) {
		super(cause);
		this.errorCode = errorCode;
	}

	public CheckPasswordException(String message, Throwable cause, CheckPasswordErrorCode errorCode) {
		super(message, cause);
		this.errorCode = errorCode;
	}

	public CheckPasswordErrorCode getErrorCode() {
		return this.errorCode;
	}
}
