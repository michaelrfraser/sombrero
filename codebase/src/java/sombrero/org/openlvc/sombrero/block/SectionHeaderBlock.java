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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.openlvc.sombrero.PcapConstants;
import org.openlvc.sombrero.io.Endianness;

/**
 * Represents a Section Header Block (SHB) within a pcapng capture file.
 * <p/>
 * The SHB identifies the beginning of a section of the capture file. The Section Header Block 
 * does not contain data but it rather identifies a list of blocks (interfaces, packets) that are 
 * logically correlated.
 * <p/>
 * For a description of the SHB and optional metadata values that can be stored against it, please
 * see section 4.1 of the IETF pcapng specification.
 */
public class SectionHeaderBlock implements IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private Endianness endianness;
	private int majorVersion;
	private int minorVersion;
	private List<PcapOption> options;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * SectionHeaderBlock constructor with specified values
	 * 
	 * @param endianness the endianness that the section's child blocks are encoded in  
	 * @param majorVersion the major version of the pcapng format that the section and its contents
	 *                     comply with 
	 * @param minorVersion the minor version of the pcapng format that the section and its contents
	 *                     comply with
	 * @param options metadata values stored against the section by the capturer
	 * 
	 * @see Endianness
	 * @see PcapOption
	 */
	public SectionHeaderBlock( Endianness endianness, 
	                           int majorVersion, 
	                           int minorVersion,
	                           List<PcapOption> options )
	{
		this.endianness = endianness;
		this.majorVersion = majorVersion;
		this.minorVersion = minorVersion;
		this.options = new ArrayList<>( options ); 
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// IPcapBlock Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return {@link PcapConstants#BLOCKTYPE_SHB} indicating this is a SectionHeaderBlock
	 */
	@Override
	public long getType()
	{
		return PcapConstants.BLOCKTYPE_SHB;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the {@link Endianness} that the section's child blocks are encoded in
	 */
	public Endianness getEndianness()
	{
		return this.endianness;
	}
	
	/**
	 * @return the major version of the pcapng format that the section and its contents comply with 
	 * @see #getMinorVersion()
	 */
	public int getMajorVersion()
	{
		return this.majorVersion;
	}
	
	/**
	 * @return the minor version of the pcapng format that the section and its contents comply with 
	 * @see #getMajorVersion()
	 */
	public int getMinorVersion()
	{
		return this.minorVersion;
	}
	
	/**
	 * @return option values stored against this section by the capturer
	 * @see PcapOption
	 */
	public List<PcapOption> getOptions()
	{
		return new ArrayList<>( this.options );
	}
	
	/**
	 * @return the description of the hardware used to create this section, or <code>null</code> if
	 *         that information was not provided by the capturer
	 * @see PcapConstants#OPT_SHB_HARDWARE
	 */
	public String getHardware()
	{
		Optional<PcapOption> hardwareOption = PcapOption.getOption( this.options, 
		                                                            PcapConstants.OPT_SHB_HARDWARE );
		
		if( hardwareOption.isPresent() )
			return hardwareOption.get().getStringValue();
		else
			return null;
	}
	
	/**
	 * @return the the name of the operating system used to create this section, or 
	 *         <code>null</code> if that information was not provided by the capturer
	 * @see PcapConstants#OPT_SHB_OS
	 */
	public String getOperatingSystem()
	{
		Optional<PcapOption> osOption = PcapOption.getOption( this.options, 
		                                                            PcapConstants.OPT_SHB_OS );
		
		if( osOption.isPresent() )
			return osOption.get().getStringValue();
		else
			return null;
	}
	
	/**
	 * @return the name of the application used to create this section, or <code>null</code> if that
	 *         information was not provided by the capturer
	 * @see PcapConstants#OPT_SHB_USERAPPL
	 */
	public String getUserApplication()
	{
		Optional<PcapOption> userApplOption = PcapOption.getOption( this.options, 
		                                                            PcapConstants.OPT_SHB_USERAPPL );
		
		if( userApplOption.isPresent() )
			return userApplOption.get().getStringValue();
		else
			return null;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
