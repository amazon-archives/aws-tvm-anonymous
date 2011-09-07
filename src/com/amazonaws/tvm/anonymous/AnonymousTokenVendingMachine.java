/*
 * Copyright 2010-2011 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazonaws.tvm.anonymous;

import static com.amazonaws.tvm.Utilities.encode;
import static javax.servlet.http.HttpServletResponse.SC_CONFLICT;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_REQUEST_TIMEOUT;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import java.util.logging.Logger;

import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.tvm.TemporaryCredentialManagement;
import com.amazonaws.tvm.TokenVendingMachineLogger;
import com.amazonaws.tvm.Utilities;
import com.amazonaws.tvm.custom.DeviceAuthentication;

/**
 * This class implements functions for Anonymous mode. It allows to register new devices and specify the encryption key to be used for this device in
 * future communication. This class allows a registered device to make token request. The request is validated using signature and granted tokens if 
 * signature is valid. The tokens are encrypted using the key corresponding to the device UID so that it can be decrypted back by the same device only. 
 */
public class AnonymousTokenVendingMachine {
	
	public static final Logger log = TokenVendingMachineLogger.getLogger();
	
	/**
	 * Verify if the token request is valid. UID is authenticated. The timestamp is checked to see it falls within the valid timestamp window. The
	 * signature is computed and matched against the given signature. Useful in Anonymous and Identity modes
	 * 
	 * @param uid
	 *            Unique device identifier
	 * @param signature
	 *            Base64 encoded HMAC-SHA256 signature derived from key and timestamp
	 * @param timestamp
	 *            Timestamp of the request in ISO8601 format
	 * @return status code indicating if token request is valid or not
	 * @throws Exception
	 */
	public int validateTokenRequest( String uid, String signature, String timestamp ) throws Exception {
		if ( !Utilities.isTimestampValid( timestamp ) ) {
			log.warning( "Timestamp : " + encode( timestamp ) + " not valid. Setting Http status code " + SC_REQUEST_TIMEOUT );
			return SC_REQUEST_TIMEOUT;
		}
		
		log.fine( String.format( "Timestamp [ %s ] is valid", encode( timestamp ) ) );
		
		DeviceAuthentication auth = new DeviceAuthentication();
		String key = auth.getKey( uid );
		
		if ( !this.authenticateSignature( key, timestamp, signature ) ) {
			log.warning( "Client signature doesnot match with server generated signature .Setting Http status code " + SC_UNAUTHORIZED );
			return SC_UNAUTHORIZED;
		}
		
		log.fine( "Signature matched!!!" );
		return SC_OK;
	}
	
	/**
	 * Generate tokens for given UID. The tokens are encrypted using the key corresponding to UID. Encrypted tokens are then wrapped in JSON object
	 * before returning it. Useful in Anonymous and Identity modes
	 * 
	 * @param uid
	 *            Unique device identifier
	 * @return encrypted tokens as JSON object
	 * @throws Exception
	 */
	public String getToken( String uid ) throws Exception {
		
		DeviceAuthentication auth = new DeviceAuthentication();
		String key = auth.getKey( uid );
		
		Credentials sessionCredentials = TemporaryCredentialManagement.getTemporaryCredentials( uid );
		// if unable to create session credentials then return HTTP 500 error code
		if ( sessionCredentials == null ) {
			return null;
		}
		else {
			log.info( "Generating session tokens for UID : " + encode( uid ) );
			String data = Utilities.prepareJsonResponseForTokens( sessionCredentials, key );
			if ( null == data ) {
				log.severe( "Error generating xml response for token request" );
				return null;
			}
			return data;
		}
	}
	
	/**
	 * Allows user device (e.g. mobile) to register with Token Vending Machine (TVM). This function is useful in Anonymous mode
	 * 
	 * @param uid
	 *            Unique device identifier
	 * @param key
	 *            Secret piece of information
	 * @return status code indicating if the registration was successful or not
	 * @throws Exception
	 */
	public int registerDevice( String uid, String key ) throws Exception {
		DeviceAuthentication authenticator = new DeviceAuthentication();
		boolean deviceWasRegistered = authenticator.registerDevice( uid, key );
		
		if ( deviceWasRegistered ) {
			log.warning( "Device successfully registered. Setting Http status code " + SC_OK );
			return SC_OK;
		}
		else {
			log.warning( "Device registration failed. Setting Http status code " + SC_CONFLICT );
			return SC_CONFLICT;
		}
	}
	
	/**
	 * Verify if the given signature is valid.
	 * 
	 * @param key
	 *            The key used in the signature process
	 * @param timestamp
	 *            The timestamp of the request in ISO8601 format
	 * @param signature
	 *            Base64 encoded HMAC-SHA256 signature derived from key and timestamp
	 * @return true if computed signature matches with the given signature, false otherwise
	 * @throws Exception
	 */
	private boolean authenticateSignature( String key, String timestamp, String signature ) throws Exception {
		if ( null == key ) {
			log.warning( "Key not found" );
			return false;
		}
		
		String computedSignature = Utilities.sign( timestamp, key );

		return Utilities.slowStringComparison(signature, computedSignature);
	}
	
}
