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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.openlvc.sombrero.PcapConstants;

/**
 * An Interface Description Block (IDB) is the container for information describing an interface on
 * which packet data is captured
 * <p/>
 * For a description of the IDB and optional metadata values that can be stored against it, please
 * see section 4.2 of the IETF pcapng specification.
 */
public class InterfaceDescriptionBlock implements IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int linkType;
	private int snapLength;
	private List<PcapOption> options;
	
	private Instant timestampOffset;
	private ChronoUnit timestampResolution;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for InterfaceDescriptionBlock with specified values.
	 * <p/>
	 * Standard link layer type values are defined Section 2.1 of the IETF `PCAP and PCAPNG LINKTYPE 
	 * Registry` document.
	 * 
	 * @param linkType the link layer type of this interface.
	 * @param snapLength the maximum number of octets that will be captured for each packet 
	 * @param options optional metadata values provided by the capturer
	 */
	public InterfaceDescriptionBlock( int linkType, 
	                                  int snapLength, 
	                                  Collection<PcapOption> options )
	{
		this.linkType = linkType;
		this.snapLength = snapLength;
		this.options = new ArrayList<>( options );
		
		// Following values are from options and will be calculated on demand
		this.timestampOffset = null;
		this.timestampResolution = null;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// IPcapBlock Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return {@link PcapConstants#BLOCKTYPE_IDB} indicating this is an InterfaceDescriptionBlock
	 */
	@Override
	public long getType()
	{
		return PcapConstants.BLOCKTYPE_IDB;
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the link layer type of this interface
	 */
	public int getLinkType()
	{
		return this.linkType;
	}
	
	/**
	 * @return the maximum number of octets captured from each packet
	 */
	public int getSnapLength()
	{
		return this.snapLength;
	}
	
	/**
	 * @return option values stored against this interface by the capturer
	 * @see PcapOption
	 */
	public List<PcapOption> getOptions()
	{
		return new ArrayList<>( this.options );
	}
	
	/**
	 * @return the name of the device used to capture data, or <code>null</code> if that information
	 *         was not provided by the capturer
	 * @see PcapConstants#OPT_IF_NAME
	 */
	public String getName()
	{
		Optional<PcapOption> nameOption = PcapOption.getOption( options, 
			                                                    PcapConstants.OPT_IF_NAME );
		if( nameOption.isPresent() )
			return nameOption.get().getStringValue();
		else
			return null;
	}
	
	/**
	 * @return the description of the device used to capture data, or <code>null</code> if that 
	 *         information was not provided by the capturer
	 * @see PcapConstants#OPT_IF_DESCRIPTION
	 */
	public String getDescription()
	{
		Optional<PcapOption> descriptionOption = PcapOption.getOption( options, 
		                                                               PcapConstants.OPT_IF_DESCRIPTION );
		if( descriptionOption.isPresent() )
			return descriptionOption.get().getStringValue();
		else
			return null;
	}
	
	/**
	 * @return the name of the operating system of the machine in which this interface is installed,
	 *         or <code>null</code> if that information was not provided by the capturer
	 * @see PcapConstants#OPT_IF_OS
	 */
	public String getOperatingSystem()
	{
		Optional<PcapOption> osOption = PcapOption.getOption( options, 
			                                                  PcapConstants.OPT_IF_OS );
		if( osOption.isPresent() )
			return osOption.get().getStringValue();
		else
			return null;
	}
	
	/**
	 * @return the offset that must be added to the time stamp of each packet to obtain the absolute 
	 *         time stamp of a packet\
	 * @see PcapConstants#OPT_IF_TSOFFSET
	 */
	public Instant getTimestampOffset()
	{
		if( this.timestampOffset == null )
		{
			this.timestampOffset = PcapConstants.DEFAULT_TIMSTAMPOFFSET;
			Optional<PcapOption> tsOffsetOption = PcapOption.getOption( options, 
			                                                            PcapConstants.OPT_IF_TSOFFSET );
			if( tsOffsetOption.isPresent() )
			{
				long offsetSeconds = tsOffsetOption.get()
				                                   .getNumberValue()
				                                   .longValue();
				this.timestampOffset = Instant.ofEpochSecond( offsetSeconds );
			}
		}
		
		return this.timestampOffset;
	}
	
	/**
	 * @return the resolution of packet time stamps captured against this interface
	 * @see PcapConstants#OPT_IF_TSRESOL
	 */
	public ChronoUnit getTimestampResolution()
	{
		if( this.timestampResolution == null )
		{
			this.timestampResolution = PcapConstants.DEFAULT_TIMESTAMPRESOLUTION;
			Optional<PcapOption> tsResolOption = 
				PcapOption.getOption( options, PcapConstants.OPT_IF_TSRESOL );
			
			if( tsResolOption.isPresent() )
			{
				int tsResolValue = tsResolOption.get().getNumberValue().intValue();
				switch( tsResolValue )
				{
					case 1:
						this.timestampResolution = ChronoUnit.SECONDS;
						break;
					case 3:
						this.timestampResolution = ChronoUnit.MILLIS;
						break;
					case 6:
						this.timestampResolution = ChronoUnit.MICROS;
						break;
					case 9:
						this.timestampResolution = ChronoUnit.NANOS;
						break;
					default:
						throw new IllegalArgumentException( "unsupported OPT_IF_TSRESOL value: " +
						                                    tsResolValue );
				}
			}
		}
		return this.timestampResolution;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
