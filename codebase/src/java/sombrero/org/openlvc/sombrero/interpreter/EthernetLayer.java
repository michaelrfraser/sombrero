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

/**
 * Represents Ethernet level information defined within a network packet 
 */
public class EthernetLayer extends ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private byte[] destAddress;
	private byte[] sourceAddress;
	private int type;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for EthernetLayer with specified values
	 * <p/>
	 * See https://en.wikipedia.org/wiki/EtherType for a complete list of ethertypes
	 *  
	 * @param destAddress the destination MAC address
	 * @param sourceAddress the source MAC addresss
	 * @param type the ethertype of the data contained within this frame 
	 * @param data the data payload of this frame
	 */
	public EthernetLayer( byte[] destAddress, 
	                      byte[] sourceAddress, 
	                      int type, 
	                      byte[] data )
	{
		super( data );
		
		this.destAddress = destAddress;
		this.sourceAddress = sourceAddress;
		this.type = type;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the MAC address of the network interface this packet was sent to
	 */
	public byte[] getDestAddress()
	{
		return this.destAddress;
	}
	
	/**
	 * @return the MAC address of the network interface this packet was sent from
	 */
	public byte[] getSourceAddress()
	{
		return this.sourceAddress;
	}
	
	/**
	 * See https://en.wikipedia.org/wiki/EtherType for a complete list of ethertypes
	 * 
	 * @return the ethertype of the data contained within this frame's data payload
	 */
	public int getType()
	{
		return this.type;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
