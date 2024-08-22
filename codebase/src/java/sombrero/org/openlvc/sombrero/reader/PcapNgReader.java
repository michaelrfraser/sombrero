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
package org.openlvc.sombrero.reader;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.openlvc.sombrero.PcapConstants;
import org.openlvc.sombrero.PcapException;
import org.openlvc.sombrero.block.EnhancedPacketBlock;
import org.openlvc.sombrero.block.IPcapBlock;
import org.openlvc.sombrero.block.InterfaceDescriptionBlock;
import org.openlvc.sombrero.block.InterfaceStatisticsBlock;
import org.openlvc.sombrero.block.PcapOption;
import org.openlvc.sombrero.block.SectionHeaderBlock;
import org.openlvc.sombrero.block.UnsupportedBlock;
import org.openlvc.sombrero.io.Endianness;
import org.openlvc.sombrero.io.PcapInputStream;

/**
 * An {@link IPcapReader} implementation for reading pcapng files
 */
public class PcapNgReader implements IPcapReader
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private Endianness endianness;
	private InputStream masterStream;
	private PcapInputStream slaveStream;
	private List<InterfaceDescriptionBlock> ifaceDefinitions;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	public PcapNgReader( InputStream in )
	{
		this.endianness = Endianness.Big;
		this.masterStream = new BufferedInputStream( in );
		this.ifaceDefinitions = new ArrayList<>();
		this.slaveStream = null;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	
	////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////// IPcapParser Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	@Override
	public IPcapBlock nextBlock() throws IOException, PcapException
	{
		if( this.masterStream.available() < 12 )
			return null;
		
		// If this is an SHB, then update the state machine
		this.masterStream.mark( 12 );
		byte[] typeRaw = this.masterStream.readNBytes( 4 );
		if( Arrays.equals(typeRaw, PcapConstants.getPcapNgShbPalindrome()) )
		{
			masterStream.skipNBytes( 4 ); // skip over size for now
			this.endianness = (masterStream.read() & 0xFF) == 0x1A ? Endianness.Big 
			                                                       : Endianness.Little;
			this.ifaceDefinitions.clear();
		}
		
		this.masterStream.reset();
		
		// Read the next block for real
		slaveStream = PcapInputStream.create( this.masterStream, this.endianness );
		long type = slaveStream.readUint32();
		int bodyLength = (int)slaveStream.readUint32() - 12;
		
		IPcapBlock block = null;
		if( type == PcapConstants.BLOCKTYPE_SHB )
			block = readSectionHeader( slaveStream, bodyLength );
		else if( type == PcapConstants.BLOCKTYPE_IDB )
			block = readInterfaceDescription( slaveStream, bodyLength );
		else if( type == PcapConstants.BLOCKTYPE_EPB )
			block = readEnhancedPacketBlock( slaveStream, bodyLength );
		else if( type == PcapConstants.BLOCKTYPE_ISB )
			block = readInterfaceStatisticsBlock( slaveStream, bodyLength );
		else
			block = readUnsupportedPacketBlock( type, slaveStream, bodyLength );
		
		slaveStream.readUint32(); // Redundant length value
		
		if( block.getType() == PcapConstants.BLOCKTYPE_IDB )
			this.ifaceDefinitions.add( (InterfaceDescriptionBlock)block );
		
		return block;
	}
	
	private SectionHeaderBlock readSectionHeader( PcapInputStream blockStream, 
	                                              int bodyLength ) throws IOException
	{
		Endianness sectionEndianness = blockStream.readUint32() == 0x1A2B3C4DL ? Endianness.Big 
		                                                                       : Endianness.Little;
		int majorVersion = blockStream.readUint16();
		int minorVersion = blockStream.readUint16();
		blockStream.readUint64(); // Section length
		
		List<PcapOption> options = new ArrayList<>();
		if( bodyLength > 16 )
			options.addAll( readOptions(blockStream) );
		
		return new SectionHeaderBlock( sectionEndianness, 
		                               majorVersion, 
		                               minorVersion, 
		                               options );
	}
	
	private InterfaceDescriptionBlock readInterfaceDescription( PcapInputStream blockStream, 
	                                                            int bodyLength ) 
		throws IOException
	{
		int linkType = blockStream.readUint16();
		blockStream.skipNBytes( 2 );  // Reserved
		int snapLength = (int)blockStream.readUint32();
		
		List<PcapOption> options = new ArrayList<>();
		if( bodyLength > 8 )
			options.addAll( readOptions(blockStream) );
		
		return new InterfaceDescriptionBlock( linkType, 
		                                      snapLength, 
		                                      options );
	}
	
	private EnhancedPacketBlock readEnhancedPacketBlock( PcapInputStream blockStream, 
	                                                     int bodyLength ) 
		 throws IOException, PcapException
	{
		//
		// Interface that captured the packet
		//
		int ifaceId = (int)blockStream.readUint32();
		InterfaceDescriptionBlock iface = ifaceDefinitions.get( ifaceId );
		if( iface == null )
			throw new PcapException( "reference to unknown iface index %d", ifaceId );
		
		//
		// Time that the packet was captured at
		//
		long timestampUpper = blockStream.readUint32();
		long timestampLower = blockStream.readUint32();
		long timeUnits = timestampUpper << 32 | timestampLower;
		
		// Calculate the timestamp using the interface's reference frame
		Instant tsOffset = iface.getTimestampOffset();
		ChronoUnit tsResolution = iface.getTimestampResolution();
		Instant timestamp = tsOffset.plus( Duration.of(timeUnits, tsResolution) );
		
		//
		// Captured packet data
		//
		int capturedLength = (int)blockStream.readUint32();
		int originalLength = (int)blockStream.readUint32();
		
		// Sanity check against snaplen. Can get a massive value here if the file has been corrupted
		// and we don't want to blow up the stack with a huge alloc
		int snapLen = iface.getSnapLength();
		if( snapLen != PcapConstants.SNAPLEN_UNLIMITED && capturedLength > snapLen )
		{
			throw new PcapException( "captured packet size exceeds interface snaplen (snaplen=%d, captured=%d)", 
			                         snapLen, 
			                         capturedLength );
		}
		
		byte[] packetData = new byte[capturedLength];
		blockStream.readFully( packetData );
		
		int paddingBytes = capturedLength % 4;
		int skipBytes = 0;
		if( paddingBytes > 0 )
		{
			skipBytes = 4 - paddingBytes;
			blockStream.skipNBytes( skipBytes );
		}
		
		//
		// Packet-level options
		//
		List<PcapOption> options = new ArrayList<>();
		if( bodyLength > 20 + capturedLength + skipBytes )
			options.addAll( readOptions(blockStream) );
		
		return new EnhancedPacketBlock( iface, 
		                                timestamp, 
		                                originalLength, 
		                                packetData, 
		                                options );
	}
	
	private InterfaceStatisticsBlock readInterfaceStatisticsBlock( PcapInputStream blockStream, 
	                                                               int bodyLength )
		throws IOException, PcapException
	{
		//
		// Interface that captured the packet
		//
		int ifaceId = (int)blockStream.readUint32();
		InterfaceDescriptionBlock iface = ifaceDefinitions.get( ifaceId );
		if( iface == null )
			throw new PcapException( "reference to unknown iface index %d", ifaceId );
		
		//
		// Time that the packet was captured at
		//
		long timestampUpper = blockStream.readUint32();
		long timestampLower = blockStream.readUint32();
		long timeUnits = timestampUpper << 32 | timestampLower;
		
		// Calculate the timestamp using the interface's reference frame
		Instant tsOffset = iface.getTimestampOffset();
		ChronoUnit tsResolution = iface.getTimestampResolution();
		Instant timestamp = tsOffset.plus( Duration.of(timeUnits, tsResolution) );
		
		//
		// Statistic values
		//
		List<PcapOption> values = new ArrayList<>();
		if( bodyLength > 12 )
			values.addAll( readOptions(blockStream) );
		
		return new InterfaceStatisticsBlock( iface, timestamp, values );
	}
	
	private UnsupportedBlock readUnsupportedPacketBlock( long type,
	                                                     PcapInputStream blockStream, 
	                                                     int bodyLength ) throws IOException
	{
		byte[] content = new byte[bodyLength];
		blockStream.readFully( content, 0, bodyLength );
		
		return new UnsupportedBlock( type, content );
	}
	
	private PcapOption readOption( PcapInputStream stream ) throws IOException
	{
		int type = stream.readUint16();
		int length = stream.readUint16();
		byte[] value = new byte[length];
		
		if( length > 0 )
		{
			stream.readFully( value );
			long paddingBytes = (length % 4);
			if( paddingBytes > 0 )
				stream.skipNBytes( 4 - paddingBytes );
		}
		
		return new PcapOption( type, stream.getEndianness(), value );
	}
	
	private List<PcapOption> readOptions( PcapInputStream stream ) throws IOException
	{
		List<PcapOption> options = new ArrayList<>();
		
		PcapOption option = readOption( stream );
		while( option.id() != PcapConstants.OPT_ENDOFOPT )
		{
			options.add( option );
			option = readOption( stream );
		}
		
		return options;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	protected static boolean isPcapNgHeader( byte[] idBlock )
	{
		if( idBlock.length < 1 )
			throw new IllegalArgumentException( "idBlock must be at least 1 byte long" );
		
		int uint8at0 = idBlock[0] & 0xFF;
		return uint8at0 == 0x0A;
	}
}
