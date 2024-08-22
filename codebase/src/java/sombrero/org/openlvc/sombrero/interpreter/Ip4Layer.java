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

import java.net.InetAddress;

/**
 * Represents Internet Protocol v4 information defined within a network packet
 */
public class Ip4Layer extends ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int typeOfService;
	private int identification;
	private int flags;
	private int fragmentOffset;
	private int ttl;
	private int protocol;
	private int checksum;
	private InetAddress sourceAddr;
	private InetAddress destAddress;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for Ip4Layer with specified values
	 * <p/>
	 * See https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers for a complete list of IP
	 * protocol numbers 
	 * 
	 * @param parent the parent layer in the protocol stack (usually Ethernet or Raw)
	 * @param typeOfService the IP packet's Type of Service field
	 * @param identification the IP packet's fragmentation identifier 
	 * @param flags the IP packet's fragmentation flags
	 * @param fragmentOffset the position of the fragment in the original fragmented IP packet
	 * @param ttl the IP packet's time to live
	 * @param protocol the protocol that is encapsulated within the IP packet
	 * @param checksum the header checksum
	 * @param sourceAddress the IP Address of the packet's sender
	 * @param destAddress the IP Address of the packet's destination
	 * @param data the IP packet's data
	 */
	public Ip4Layer( ProtocolLayer parent,
	                 int typeOfService,
	                 int identification,
	                 int flags,
	                 int fragmentOffset,
	                 int ttl,
	                 int protocol,
	                 int checksum,
	                 InetAddress sourceAddress,
	                 InetAddress destAddress,
	                 byte[] data )
	{
		super( parent, data );
		this.typeOfService = typeOfService;
		this.identification = identification;
		this.flags = flags;
		this.fragmentOffset = fragmentOffset;
		this.ttl = ttl;
		this.protocol = protocol;
		this.checksum = checksum;
		this.sourceAddr = sourceAddress;
		this.destAddress = destAddress;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the IP packet's Type of Service field
	 */
	public int getTypeOfService()
	{
		return this.typeOfService;
	}
	
	/**
	 * @return the IP packet's fragmentation identifier
	 */
	public int getIdentification()
	{
		return this.identification;
	}
	
	/** 
	 * @return the IP packet's fragmentation flags
	 */
	public int getFlags()
	{
		return this.flags;
	}
	
	/**
	 * @return the position of the fragment in the original fragmented IP packet
	 */
	public int getFragmentOffset()
	{
		return this.fragmentOffset;
	}
	
	/**
	 * @return the IP packet's time to live
	 */
	public int getTimeToLive()
	{
		return this.ttl;
	}
	
	/**
	 * @return the protocol that is encapsulated within the IP packet's data payload
	 */
	public int getProtocol()
	{
		return this.protocol;
	}
	
	/**
	 * @return the header checksum
	 */
	public int getChecksum()
	{
		return this.checksum;
	}
	
	/**
	 * @return the IP Address of the packet's sender
	 */
	public InetAddress getSourceAddress()
	{
		return this.sourceAddr;
	}
	
	/**
	 * @return the IP Address of the packet's destination
	 */
	public InetAddress getDestAddress()
	{
		return this.destAddress;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
