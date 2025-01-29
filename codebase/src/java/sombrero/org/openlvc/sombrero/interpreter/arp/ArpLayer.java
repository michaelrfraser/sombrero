/*
 *   Copyright 2024 Open LVC Project.
 *
 *   This file is part of Open LVC Sombrero.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package org.openlvc.sombrero.interpreter.arp;

import java.net.InetAddress;

import org.openlvc.sombrero.interpreter.ProtocolLayer;

/**
 * Represents Address Resolution Protocol information defined within a network packet
 */
public class ArpLayer extends ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int hardwareType;
	private int protocolType;
	private int operation;
	private byte[] senderHardwareAddress;
	private byte[] senderProtocolAddress;
	private byte[] targetHardwareAddress;
	private byte[] targetProtocolAddress;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for ArpLayer with specified values
	 * 
	 * @param parent the parent layer in the protocol stack (usually Ethernet or Raw)
	 * @param data the ARP packet's data
	 */
	public ArpLayer( ProtocolLayer parent,
	                 int hardwareType,
	                 int protocolType,
	                 int operation,
	                 byte[] senderHardwareAddress,
	                 byte[] senderProtocolAddress,
	                 byte[] targetHardwareAddress,
	                 byte[] targetProtocolAddress )
	{
		super( parent, null );
		this.hardwareType = hardwareType;
		this.protocolType = protocolType;
		this.operation = operation;
		this.senderHardwareAddress = senderHardwareAddress;
		this.senderProtocolAddress = senderProtocolAddress;
		this.targetHardwareAddress = targetHardwareAddress;
		this.targetProtocolAddress = targetProtocolAddress;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	@Override
	public String toString()
	{
		return String.format( "ARP: " );
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
