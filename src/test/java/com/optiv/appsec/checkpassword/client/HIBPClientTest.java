package com.optiv.appsec.checkpassword.client;

import static org.junit.Assert.*;

import org.junit.Test;

import com.optiv.appsec.checkpassword.exception.CheckPasswordException;

public class HIBPClientTest {

	@Test
	public void validateChecksExecuteProperly() throws CheckPasswordException {
		HIBPClient client = new HIBPClient("Test Client");
				
		assertFalse(client.check("password"));
		assertFalse(client.check("Password1"));
		assertFalse(client.check("Optiv"));
		assertTrue(client.check("ey5IDR3l5Lp75ocNRcQn"));
		assertTrue(client.check("diugtVhokeQykrWe3ZUe"));
	}
	
	@Test
	public void verifySha1CalculatesProperly() throws CheckPasswordException {
		assertEquals("2F960C7436AE0BBD409C522D3FA081D05B077395", HIBPClient.sha1Hex("A test string"));
		assertEquals("70CCD9007338D6D81DD3B6271621B9CF9A97EA00", HIBPClient.sha1Hex("Password1"));
		assertEquals("8C283ADEBA830D3D086807FE53EA168B4EC320D2", HIBPClient.sha1Hex("Optiv"));
		assertEquals("5EC59EFD9AD699D6130E07AD33DDAC2A1D04F4F8", HIBPClient.sha1Hex("ey5IDR3l5Lp75ocNRcQn"));
		assertEquals("47DE7C93AB6BD5E80A3AFE37E57FF51E1A63D9C9", HIBPClient.sha1Hex("diugtVhokeQykrWe3ZUe"));
	}
}
