/*
 * Copyright 2010-2012 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.amazonaws.tvm.RootServlet;
import com.amazonaws.tvm.Utilities;

public class RegisterDeviceServlet extends RootServlet {
	
	protected String processRequest( HttpServletRequest request, HttpServletResponse response ) throws Exception {
		log.info( "entering processRequest" );
		try {
			
			AnonymousTokenVendingMachine anonymousTokenVendingMachine = new AnonymousTokenVendingMachine();
			
			String uid = super.getRequiredParameter( request, "uid" );
			String key = super.getRequiredParameter( request, "key" );
			
			if( !Utilities.isValidUID(uid) || !Utilities.isValidKey(key)) { 
				log.warning("Input not valid");
				super.sendErrorResponse(HttpServletResponse.SC_BAD_REQUEST, response);
				return null;				
			}
			
			int responseCode = anonymousTokenVendingMachine.registerDevice( uid, key );
			
			if ( responseCode != HttpServletResponse.SC_OK ) {
				log.warning( "Device registration failed. Setting Http status code " + responseCode );
				super.sendErrorResponse( responseCode, response );
				return null;
			}
			
			log.warning( "Device successfully registered. Setting Http status code " + HttpServletResponse.SC_OK );
			super.sendOKResponse( response, null );
			return null;
		}
		finally {
			log.info( "leaving processRequest" );
		}
	}
	
}
