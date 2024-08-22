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
package org.openlvc.sombrero.block;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.openlvc.sombrero.PcapConstants;

/**
 * An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the 
 * network.
 * <p/>
 * For a description of the EPB and optional metadata values that can be stored against it, please
 * see section 4.3 of the IETF pcapng specification.
 */
public class EnhancedPacketBlock implements IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//---------------------------------------------------------- 

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private InterfaceDescriptionBlock iface;
	private Instant timestamp;
	private int originalLength;
	private byte[] packetData;
	private List<PcapOption> options;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for EnhancedPacketBlock with specified values
	 * 
	 * @param iface the description of the network interface that this packet was captured from
	 * @param timestamp the time that this packet was captured
	 * @param originalLength the original data length of this packet (the packet may have been
	 *                       truncated depending on capturer size limits)
	 * @param packetData the captured packet's data
	 * @param options optional metadata values stored against the packet by the capturer
	 */
	public EnhancedPacketBlock( InterfaceDescriptionBlock iface,
	                            Instant timestamp,
	                            int originalLength,
	                            byte[] packetData,
	                            Collection<PcapOption> options )
	{
		this.iface = iface;
		this.timestamp = timestamp;
		this.originalLength = originalLength;
		this.packetData = packetData;
		this.options = new ArrayList<>( options );
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// IPcapBlock Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return {@link PcapConstants#BLOCKTYPE_EPB} indicating this is an EnhancedPacketBlock
	 */
	@Override
	public long getType()
	{
		return PcapConstants.BLOCKTYPE_EPB;
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the {@link InterfaceDescriptionBlock} describing the network interface this packet 
	 *         was captured on
	 */
	public InterfaceDescriptionBlock getInterface()
	{
		return this.iface;
	}
	
	/**
	 * @return an {@link Instant} representing the time this packet was captured
	 */
	public Instant getTimestamp()
	{
		return this.timestamp;
	}
	
	/**
	 * Returns the original length, in bytes, of this packet's data.
	 * <p/>
	 * The {@link InterfaceDescriptionBlock} of the network interface this packet has been captured 
	 * on may specify a maximum number of bytes that can be captured for each packet via the Snap 
	 * Length field. Data beyond this limit will be discarded.
	 * <p/>
	 * You can check to see if this packet has been truncated by calling {@link #isTruncated()}.
	 * 
	 * @return the original length, in bytes, of this packet's data
	 * 
	 * @see #isTruncated()
	 * @see InterfaceDescriptionBlock#getSnapLength()
	 */
	public int getOriginalLength()
	{
		return this.originalLength;
	}
	
	/**
	 * Returns the data that was captured for this packet.
	 * <p/>
	 * The {@link InterfaceDescriptionBlock} of the network interface this packet has been captured 
	 * on may specify a maximum number of bytes that can be captured for each packet via the Snap 
	 * Length field. Data beyond this limit will be discarded.
	 * <p/>
	 * You can check to see if this packet has been truncated by calling {@link #isTruncated()}.
	 * 
	 * @return the data that was captured for this packet.
	 * 
	 * @see #isTruncated()
	 * @see InterfaceDescriptionBlock#getSnapLength()
	 */
	public byte[] getPacketData()
	{
		return this.packetData;
	}
	
	/**
	 * @return <code>true</code> if this packet's data was truncated due to snap length constraints,
	 *         otherwise <code>false</code> if this packet's data was captured in its entirety
	 */
	public boolean isTruncated()
	{
		return this.packetData.length < this.originalLength;
	}

	/**
	 * @return optional metadata values stored against the packet by the capturer
	 */
	public List<PcapOption> getOptions()
	{
		return new ArrayList<>( this.options );
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
