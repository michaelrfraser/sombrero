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
package org.openlvc.sombrero.interpreter;

import java.net.DatagramPacket;
import java.net.InetAddress;

/**
 * Represents User Datagram Protocol information defined within a network packet
 */
public class UdpLayer extends ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int sourcePort;
	private int destPort;
	private int checksum;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for UdpLayer with specified values
	 * 
	 * @param parent the parent layer in the protocol stack (usually IPv4 or IPv6)
	 * @param sourcePort the sender's port number
	 * @param destPort the receiver's port number
	 * @param checksum the packet's checksum
	 * @param data the packet's data payload
	 */
	public UdpLayer( ProtocolLayer parent, 
	                 int sourcePort, 
	                 int destPort, 
	                 int checksum, 
	                 byte[] data )
	{
		super( parent, data );
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		this.checksum = checksum;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the sender's port number
	 */
	public int getSourcePort()
	{
		return this.sourcePort;
	}
	
	/**
	 * @return the receiver's port number
	 */
	public int getDestPort()
	{
		return this.destPort;
	}
	
	/**
	 * @return the packet's checksum
	 */
	public int getChecksum()
	{
		return this.checksum;
	}
	
	/**
	 * @return a {@link DatagramPacket} representation of this UDP packet
	 */
	public DatagramPacket getDatagram()
	{
		// If IPv6 support is added, then we should also add a lookup for the Ip6 parent
		Ip4Layer ip4Layer = this.findParent( Ip4Layer.class );
		InetAddress destAddr = null;
		if( ip4Layer != null )
			destAddr = ip4Layer.getDestAddress();
		
		return new DatagramPacket( getData(), 
		                           getData().length, 
		                           destAddr, 
		                           this.destPort );
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
