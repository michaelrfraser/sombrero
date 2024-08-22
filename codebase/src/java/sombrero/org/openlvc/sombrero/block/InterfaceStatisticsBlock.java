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
 * Contains capture statistics for a given interface {@link InterfaceDescriptionBlock}
 */
public class InterfaceStatisticsBlock implements IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private InterfaceDescriptionBlock iface;
	private Instant timestamp;
	private List<PcapOption> values;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for InterfaceStatisticsBlock with specified values
	 * 
	 * @param iface the description of the network interface that these statistics refer to
	 * @param timestamp the time at which the statistics were taken
	 * @param values statistic values captured against the interface
	 */
	public InterfaceStatisticsBlock( InterfaceDescriptionBlock iface, 
	                                 Instant timestamp, 
	                                 Collection<PcapOption> values )
	{
		this.iface = iface;
		this.timestamp = timestamp;
		this.values = new ArrayList<>( values );
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// IPcapBlock Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return {@link PcapConstants#BLOCKTYPE_ISB} indicating this is an InterfaceStatisticsBlock
	 */
	@Override
	public long getType()
	{
		return PcapConstants.BLOCKTYPE_ISB;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the {@link InterfaceDescriptionBlock} describing the network interface that these 
	 *         statistics refer to
	 */
	public InterfaceDescriptionBlock getInterface()
	{
		return this.iface;
	}
	
	/**
	 * @return an {@link Instant} representing the time at which the statistics were taken
	 */
	public Instant getTimestamp()
	{
		return this.timestamp;
	}

	/**
	 * @return the list of statistics that were captured for this interface
	 */
	public List<PcapOption> getValues()
	{
		return new ArrayList<>( this.values );
	}
	
	/**
	 * @return the time that traffic capture started from this interface, or <code>null</code>
	 *         if that information was not provided by the capturer 
	 * 
	 * @see PcapConstants#OPT_ISB_STARTTIME
	 * @see #getCaptureEndTime()
	 */
	public Instant getCaptureStartTime()
	{
		Optional<PcapOption> startTimeOption = 
			PcapOption.getOption( this.values, PcapConstants.OPT_ISB_STARTTIME );
		if( startTimeOption.isPresent() )
		{
			Instant offset = this.iface.getTimestampOffset();
			ChronoUnit resolution = this.iface.getTimestampResolution();
			return startTimeOption.get().getTimestampValue( offset, resolution );
		}
		else
		{
			return null;
		}
	}
	
	/**
	 * @return the time that traffic capture ended from this interface, or <code>null</code>
	 *         if that information was not provided by the capturer 
	 * 
	 * @see PcapConstants#OPT_ISB_ENDTIME
	 * @see #getCaptureStartTime()
	 */
	public Instant getCaptureEndTime()
	{
		Optional<PcapOption> endTimeOption = 
			PcapOption.getOption( this.values, PcapConstants.OPT_ISB_ENDTIME );
		if( endTimeOption.isPresent() )
		{
			Instant offset = this.iface.getTimestampOffset();
			ChronoUnit resolution = this.iface.getTimestampResolution();
			return endTimeOption.get().getTimestampValue( offset, resolution );
		}
		else
		{
			return null;
		}
	}
	
	/**
	 * @return the number of packets that were received from the interface starting at the beginning
	 *         of capture, or <code>-1</code> if that information was not provided by the capturer
	 * 
	 * @see PcapConstants#OPT_ISB_IFRECV
	 * @see #getFilterAccepted()
	 * @see #getInterfacePacketsDropped()
	 * @see #getOsPacketsDropped()
	 */
	public long getInterfacePacketsReceived()
	{
		Optional<PcapOption> ifRecvOption = PcapOption.getOption( this.values, 
		                                                          PcapConstants.OPT_ISB_IFRECV );
		if( ifRecvOption.isPresent() )
			return ifRecvOption.get().getNumberValue().longValue();
		else
			return -1;
	}
	
	/**
	 * @return the number of packets that were dropped by the interface due to lack of resources 
	 *         starting at the beginning of the capture, or <code>-1</code> if that information was 
	 *         not provided by the capturer
	 * 
	 * @see #getInterfacePacketsReceived()
	 * @see #getOsPacketsDropped()
	 * @see PcapConstants#OPT_ISB_IFDROP
	 */
	public long getInterfacePacketsDropped()
	{
		Optional<PcapOption> ifDropOption = PcapOption.getOption( this.values, 
		                                                          PcapConstants.OPT_ISB_IFDROP );
		if( ifDropOption.isPresent() )
			return ifDropOption.get().getNumberValue().longValue();
		else
			return -1;
	}
	
	/**
	 * @return the number of packets that were accepted by the capture filter starting from the 
	 *         beginning of the capture, or <code>-1</code> if that information was not provided
	 *         by the capturer
	 * 
	 * @see #getInterfacePacketsReceived()
	 * @see PcapConstants#OPT_ISB_FILTERACCEPT
	 */
	public long getFilterAccepted()
	{
		Optional<PcapOption> filterAcceptOption = 
			PcapOption.getOption( this.values, PcapConstants.OPT_ISB_FILTERACCEPT );
		
		if( filterAcceptOption.isPresent() )
			return filterAcceptOption.get().getNumberValue().longValue();
		else
			return -1;
	}
	
	/**
	 * @return the number of packets that were dropped by the operating system starting from the 
	 *         beginning of the capture, or <code>-1</code> if that information was not provided
	 *         by the capturer
	 * 
	 * @see #getInterfacePacketsReceived()
	 * @see #getInterfacePacketsDropped()
	 * @see PcapConstants#OPT_ISB_OSDROP
	 */
	public long getOsPacketsDropped()
	{
		Optional<PcapOption> osDropOption = 
			PcapOption.getOption( this.values, PcapConstants.OPT_ISB_OSDROP );
		
		if( osDropOption.isPresent() )
			return osDropOption.get().getNumberValue().longValue();
		else
			return -1;
	}
	
	/**
	 * @return the number of packets that were were delivered to the user starting from the 
	 *         beginning of the capture, or <code>-1</code> if that information was not provided
	 *         by the capturer
	 * 
	 * @see #getInterfacePacketsReceived()
	 * @see PcapConstants#OPT_ISB_USRDELIV
	 */
	public long getPacketsUserDelivered()
	{
		Optional<PcapOption> usrDelivOption = 
			PcapOption.getOption( this.values, PcapConstants.OPT_ISB_USRDELIV );
		
		if( usrDelivOption.isPresent() )
			return usrDelivOption.get().getNumberValue().longValue();
		else
			return -1;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
