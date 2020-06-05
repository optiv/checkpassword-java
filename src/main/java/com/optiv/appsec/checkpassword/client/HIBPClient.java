	
package com.optiv.appsec.checkpassword.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.math.BigInteger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import com.optiv.appsec.checkpassword.exception.CheckPasswordErrorCode;
import com.optiv.appsec.checkpassword.exception.CheckPasswordException;

/**
 * The CheckPassword class uses the haveibeenpwnd.com Pwnd Passwords
 * API to check whether a proposed password has been recovered from
 * breaches. These passwords are commonly guessed by attackers. Web
 * applications should prevent users from choosing these passwords.
 * 
 * 
 * Copyright Optiv Security Inc. 2020
 * Released under the MIT license: https://opensource.org/licenses/MIT
 * 
 * @author Steven Hartz
 * @version 1.0
 * @since 2020-05-20
 *
 */
public class HIBPClient {
	
	private static final String version = "1.0";
	private static final String userAgentPostfix = "Optiv API Client";

	// This endpoint is unlikely to change, so let's abstract it away from callers.
    private static final String baseUrlv3 = "https://api.pwnedpasswords.com/range/";
    
    // Most Java runtmes should support TLS 1.2. Some may support TLS 1.3, so we'll try.
    // The API itself doesn't support anything older than 1.2.
    private static final String[] modernTls = {"TLSv1.3", "TLSv1.2"};
    
    // This value is recommended by NIST S.P. 800-63. Applications can require longer
    // passwords, but we should not consider anything shorter to be "secure".
    // Callers should consider including a maximum length of 64-128 characters, which
    // reduces the risk of Denial of Service attacks when secure password hashing is used.
    private static final int minLength = 8;
    
    private String userAgent;
    private String userAgentStub;
    private int numRetries;
    private String apiKey;
    private int maxWait;
	private boolean exposeVersion;
    
	/**
	 * Creates a new HIBPClient. The API requires that clients provide a unique,
	 * identifying User-Agent header, which we will build from the userAgentStub
	 * provided. We recommend setting it to something like your application's name.
	 * For example:
	 *     HIBPClient("Optiv Website")
	 * 
	 * @param userAgentStub 
	 */
    public HIBPClient(String userAgentStub) {
    	
    	setMaxWait(2);
    	setNumRetries(2);
    	setExposeVersion(false);
    	setUserAgentStub(userAgentStub);
    }
    
    /**
     * The default "check" method uses the latest version of the API to check
     * if the password has been recovered from breaches.
     * 
     * @param password The password to check against the API
     * @return True if the password has not been see before, false otherwise
     * @throws CheckPasswordException
     */
    public boolean check(String password) throws CheckPasswordException {
    	return checkVersion3(password);
    }

    /**
     * Uses a specific version of the API to check if the password has been recovered
     * from breaches.
     * 
     * API versions supported by this release: 3 (newest)
     * 
     * @param password The password to check against the API
     * @return True if the password has not been see before, false otherwise
     * @throws CheckPasswordException
     */
    public boolean check(String password, int apiVersion) throws CheckPasswordException {
        
        if(apiVersion != 3){
            throw new UnsupportedOperationException();
        }
        
        return checkVersion3(password);
    }
    
    /**
     * Checks that password is at least as long as our minimum acceptable length.
     * 
     * @param password Password to check
     * @return True if password is long enough
     */
    private static boolean checkLength(String password) {
    	return password.length() >= minLength;
    }

    /**
     * Checks v3 of the API to see if the password is "secure".
     * 
     * The API securely checks a users password by accepting the first 5 hex characters (36 bits) of the
     * passwords SHA-1 hash. While SHA-1 is not a secure algorithm for passwords, there are 2**124 possible
     * hashes which could match the information sent to the server. In the event the API is compromised,
     * this is still sufficiently large that attackers cannot guess what the original password was via
     * brute-force attacks.
     * 
     * The server will respond with hex hash values (less the first 5 characters) and a number indicating
     * how many breaches this password has been recovered from. This version of the library discards the
     * latter information. By comparing our hash to each response from the API, we can determine if
     * this password has been seen before without disclosing the password to the API.
     * 
     * @param password Password to check
     * @return True if the password has not been see before ("is secure"), false otherwise
     * @throws CheckPasswordException
     */
    private boolean checkVersion3(String password) throws CheckPasswordException {
        
    	boolean lengthOK = checkLength(password);
    	if(!lengthOK)
    		return false;
    	
    	String hash = sha1Hex(password);
        
    	URL url;
        try{
        	url = new URL(baseUrlv3 + hash.substring(0, 5));
        } catch(MalformedURLException e) {
        	// This shouldn't happen in production: this URL is hardcoded.
        	throw new CheckPasswordException("API URL was malformed", CheckPasswordErrorCode.BadConfiguration);
        }

        String hashEnd = hash.substring(5);
        

        String response = requestGet(url);
        String[] commonHashes = response.split("\\r?\\n");

        // Hash values are in alphabetical order. There may be a clever
        // way to search that determines if our hash is present in
        // log(n) average time. A linear search was easier to implement.
        for(int i=0; i < commonHashes.length; i++){
        	
        	// API should respond with HASHHEX:number
        	// Any line that can't be split like that
        	// doesn't follow API v3 spec
            String[] pieces = commonHashes[i].split(":");
            if(pieces.length != 2){
                throw new CheckPasswordException("API Returned malformed response", CheckPasswordErrorCode.APICallFailure);
            }
            
            
            String testHashEnd = pieces[0];
            //String popularity = pieces[1];

            if(hashEnd.equals(testHashEnd)){
                // Our password was found in the list of compromised hashes
                return false;
            }
        }

        // If we reach here, the API did not list the hash as a compromised password
        return true;
    }

    /**
     * A helper method to keep the code clean(er). Performs an HTTP(S) GET request against
     * the URL it is given and returns the response as a String. This method is private
     * because it doesn't do deep sanity checks against its input parameters.
     * 
     * @param url A URL to make a request against
     * @return String HTTP(S) response body
     * @throws CheckPasswordException
     */
    private String requestGet(URL url) throws CheckPasswordException {
        
    	SSLContext ctx = null;
    	
    	// Try TLS algorithms until we find something we understand.
    	// Should try from newest to oldest so that we use the most secure
    	// TLS algorithm we can.
    	for(String algo : modernTls) { 
	    	try {
	        	ctx = SSLContext.getInstance(algo);
	        	break;
	        }catch(NoSuchAlgorithmException e) {
	        	// Move on to the next one
	        }
    	}
    	
    	if(ctx == null) {
    		throw new CheckPasswordException("Unable to find a supported, secure TLS version", CheckPasswordErrorCode.BadConfiguration);
    	}

    	// The initial attempt should not count as a retry, so +1    	
    	for(int attempts = getNumRetries() + 1; attempts >0; attempts--){
	    	try {
	    		// Use default security controls, including certificate checks
	    		ctx.init(null, null, null);
	    	} catch(KeyManagementException e){
	    		throw new CheckPasswordException("Connection failed: could not read keystore", e, CheckPasswordErrorCode.BadConfiguration);
	    	}
	        SSLContext.setDefault(ctx);
	
	        HttpsURLConnection connection;
	        try {
	        	connection = (HttpsURLConnection) url.openConnection();
	        } catch (IOException e) {
	        	throw new CheckPasswordException("Connection failed: HTTPS connection could not be created", e, CheckPasswordErrorCode.BadConfiguration);
	        }
	        
	        try {
	        	connection.setRequestMethod("GET");
	        	connection.setRequestProperty("User-Agent", userAgent);
	        	if(getApiKey() != null) {
	        		connection.setRequestProperty("hibp-api-key", getApiKey());
	        	}
	        } catch (ProtocolException e) {
	        	throw new CheckPasswordException("Connection failed: protocol exception", e, CheckPasswordErrorCode.APICallFailure);
	        }
	
	        
	        try {
	        	
	        	// Handle non-200 results. We can only "fix" a 429 Too Many Requests though.
	        	int status = connection.getResponseCode();
	        	if(status != 200) {
	        		if(status == 429) {
	        			String s_delay = connection.getHeaderField("retry-after");
	        			try {
	        				int delay = Integer.parseInt(s_delay);
	        				if(delay > getMaxWait()) {
	        					throw new CheckPasswordException("API retry-after delay longer than maxWait", CheckPasswordErrorCode.APICallFailure);
	        				}
	        				
	        				// sleep expects milliseconds
	        				try {
	        					Thread.sleep(delay * 1000);
	        					continue;
	        				}catch(InterruptedException ex) {
	        					throw new CheckPasswordException("Interrupted while waiting to retry request", ex, CheckPasswordErrorCode.BadConfiguration);
	        				}
	        				
	        			}catch(NumberFormatException ex) {
	        				throw new CheckPasswordException("Unparsable retry-after value from API", ex,CheckPasswordErrorCode.APICallFailure);
	        			}
	        		}
	        		else {
	        			throw new CheckPasswordException(String.format("Received status code {0} from API", status), CheckPasswordErrorCode.APICallFailure);
	        		}
	        	}
	        	
	        	// Read the response into a String because it's easier to work with.
	        	InputStream responseIS = (InputStream) connection.getInputStream();
	        	StringBuilder textBuilder = new StringBuilder();
	        	int c;
	        	while( (c = responseIS.read()) != -1 ){
	        		textBuilder.append((char) c);
	        	}
	        	String response = textBuilder.toString();
	
	        	return response;
	        } catch (IOException e) {
	        	throw new CheckPasswordException("Could not read API response", e, CheckPasswordErrorCode.APICallFailure);
	        }
    	}
    	
    	// If we were successful, we returned from inside the for loop. Only wait to get here
    	// was to exhaust our retries on a 429 Too Many Requests
    	throw new CheckPasswordException("Exhausted retries and failed to get a successful response from API", CheckPasswordErrorCode.APICallFailure);
        
    }

    /**
     * A helper method to perform SHA-1 hashes and return the result as a hex string.
     * This method is public because it seems generally useful, but remember that
     * SHA-1 is NOT a secure hashing algorithm for passwords outside of PBKDF2, and
     * may be a poor choice of hash for documents as well.
     * 
     * @param message String to hash
     * @return hashed value as a hexadecimal string (e.g. 8C283ADEBA830D3D086807FE53EA168B4EC320D2)
     * @throws SetupException
     */
    public static String sha1Hex(String message) throws CheckPasswordException {
        
    	try {
    		
    		MessageDigest md = MessageDigest.getInstance("SHA-1");
    		byte[] digest = md.digest(message.getBytes());

            BigInteger bi = new BigInteger(1, digest);
            return String.format("%0" + (digest.length << 1) + "X", bi);
            
    	} catch (NoSuchAlgorithmException e) {
    		// This should never happen; all modern Java versions require the platform to support SHA-1
    		throw new CheckPasswordException("Unable to perform SHA-1 hash, algorithm not found", CheckPasswordErrorCode.BadConfiguration);
    	}
        
    }

    /**
     * Sets how many retries to perform if a 429 Too Many Requests response is
     * received from the API. A value of 0 indicates "do not retry". The client
     * will eventually throw an error when retries are exhausted.
     * @param numRetries
     */
	public void setNumRetries(int numRetries) {
		if(numRetries < 0) {
			throw new IllegalArgumentException("Retries should not be negative");
		}
		this.numRetries = numRetries;
	}
	
	/**
	 * Returns the number of retries to perform when a 429 Too Many Requests is
	 * received from the API
	 * @return retries
	 */
	public int getNumRetries() {
		return this.numRetries;
	}
	
	/**
	 * Allows an optional API key to be provided. This is not required for the
	 * password checking endpoint.
	 * @param apiKey
	 */
	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}
	
	/**
	 * Returns the API key, if any
	 * @return String or null
	 */
	public String getApiKey() {
		return this.apiKey;	// may return null, this is fine.
	}
	
	/**
	 * When a 429 Too Many Requests is sent by the API, it includes
	 * a wait time in seconds. This client will only wait up to
	 * MaxWait seconds, or it will throw an error if the wait is unacceptably
	 * long.
	 * @param maxWait
	 */
	public void setMaxWait(int maxWait) {
		if(maxWait < 0) {
			throw new IllegalArgumentException("Wait time should be a positive number");
		}
		this.maxWait = maxWait;
	}
	
	/**
	 * The current maximum acceptable time to wait for a retry (seconds)
	 * @return
	 */
	public int getMaxWait() {
		return this.maxWait;
	}
	
	/**
	 * Instructs the API client to reveal this library's version number
	 * to the API.
	 * @param exposeVersion
	 */
	public void setExposeVersion(boolean exposeVersion) {
		this.exposeVersion = exposeVersion;

		// Changing this means our User-Agent header value needs updating
        resetUserAgent();
	}
	
	/**
	 * Whether or not the library version number will be exposed
	 * @return
	 */
	public boolean isExposeVersion() {
		return this.exposeVersion;
	}
	
	/**
	 * The API requires all clients to provide a unique User-Agent header value
	 * to identify themselves, per the acceptable use. Setting this to the name
	 * of your app is a good idea.
	 * @param userAgentStub
	 */
	public void setUserAgentStub(String userAgentStub) {
		this.userAgentStub = userAgentStub;

        // It should be impossible for the userAgentStub to
        // be out of sync with the User-Agent header we send
        // to the server, so let's make it impossible.
        resetUserAgent();
	}
	
	/**
	 * The current User-Agent stub that will identify the client.
	 * @return
	 */
	public String getUserAgentStub() {
		return this.userAgentStub;
	}
	
	/**
	 * Builds the User-Agent header value based on the current userAgentStub and 
	 * isExposeVersion settings.
	 */
	private void resetUserAgent() {
    	if (isExposeVersion()) {
    		userAgent = String.format("{0} ({1} {2})", getUserAgentStub(), userAgentPostfix, version);
    	} else {
    		userAgent = String.format("{0} ({1})", getUserAgentStub(), userAgentPostfix);
    	}
	}

}
