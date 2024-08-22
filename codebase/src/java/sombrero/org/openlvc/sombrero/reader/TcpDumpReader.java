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
import java.util.Collections;
import java.util.List;

import org.openlvc.sombrero.PcapConstants;
import org.openlvc.sombrero.PcapException;
import org.openlvc.sombrero.block.EnhancedPacketBlock;
import org.openlvc.sombrero.block.IPcapBlock;
import org.openlvc.sombrero.block.InterfaceDescriptionBlock;
import org.openlvc.sombrero.block.PcapOption;
import org.openlvc.sombrero.block.SectionHeaderBlock;
import org.openlvc.sombrero.io.Endianness;
import org.openlvc.sombrero.io.PcapInputStream;

/**
 * An {@link IPcapReader} for reading older style pcap (tcpdump) files.
 * <p/>
 * The parser will synthesize a {@link SectionHeaderBlock} and {@link InterfaceDescriptionBlock} 
 * based on the tcpdump file header. Packet entries will be represented as 
 * {@link EnhancedPacketBlock} instances.
 */
public class TcpDumpReader implements IPcapReader
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	private enum State { GenerateFakeShb, GenerateFakeIdb, Content };

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private InputStream masterStream;
	private PcapInputStream slaveStream;
	private State state;
	
	private SectionHeaderBlock fakeSectionHeader;
	private InterfaceDescriptionBlock fakeIface;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	public TcpDumpReader( InputStream in )
	{
		this.masterStream = new BufferedInputStream( in );
		this.state = State.GenerateFakeShb;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	private void readHeader() throws IOException, PcapException
	{
		if( this.state != State.GenerateFakeShb )
			throw new IllegalStateException();
		
		// Peek first byte to determine endianness
		this.masterStream.mark( 4 );
		byte[] rawMagic = masterStream.readNBytes( 4 );
		Endianness endianness = rawMagic[0] == (byte)0xA1 ? Endianness.Big 
		                                                  : Endianness.Little;
		this.masterStream.reset();
		
		// Read in all header values and generate SHB/IDB
		slaveStream = PcapInputStream.create( this.masterStream, endianness );
		
		long magic = slaveStream.readUint32(); // Magic
		if( magic != PcapConstants.TCPDUMP_HEADER_MAGIC_MICROS && 
			magic != PcapConstants.TCPDUMP_HEADER_MAGIC_NANOS )
		{
			throw new PcapException( "Not a pcap file (header magic mismatch)" );
		}
		
		byte[] tsResolFactor = magic == 
			PcapConstants.TCPDUMP_HEADER_MAGIC_NANOS ? new byte[] { (byte)0x09 }   // 10e-9 (nanos) 
			                                         : new byte[] { (byte)0x06 };  // 10e-6 (micros)
		
		int majorVersion = slaveStream.readUint16(); // Major Version
		int minorVersion = slaveStream.readUint16(); // Minor Version
		
		slaveStream.skipNBytes( 4 ); // Reserved 1
		slaveStream.skipNBytes( 4 ); // Reserved 2
		
		int snapLen = (int)slaveStream.readUint32(); // SnapLen
		
		slaveStream.readUint16();          // fcs
		int linkType = slaveStream.readUint16();     // linktype

		// Synthetic Section Header
		this.fakeSectionHeader = new SectionHeaderBlock( endianness, 
		                                                 majorVersion, 
		                                                 minorVersion, 
		                                                 new ArrayList<>() );
		
		// Synthetic Interface Description
		PcapOption ifaceTsResOption = new PcapOption( PcapConstants.OPT_IF_TSRESOL, 
		                                              endianness, 
		                                              tsResolFactor );
		List<PcapOption> ifaceOptions = Collections.singletonList( ifaceTsResOption );
		
		this.fakeIface = new InterfaceDescriptionBlock( linkType, 
		                                                snapLen, 
		                                                ifaceOptions );
	}
	
	private EnhancedPacketBlock readNextPacket() throws IOException, PcapException
	{
		if( this.state != State.Content )
			throw new IllegalStateException();
		
		if( this.masterStream.available() == 0 )
			return null;
		
		long timestampSeconds = slaveStream.readUint32();
		long timestampSubSeconds = slaveStream.readUint32();
		ChronoUnit tsResol = fakeIface.getTimestampResolution();

		Instant timestamp = Instant.ofEpochSecond( timestampSeconds )
		                           .plus( Duration.of(timestampSubSeconds, tsResol) );

		int capturedLength = (int)slaveStream.readUint32();
		int originalLength = (int)slaveStream.readUint32();

		// Sanity check against snaplen. Can get a massive value here if the file has been corrupted
		// and we don't want to blow up the stack with a huge alloc
		int snapLen = this.fakeIface.getSnapLength();
		if( snapLen != PcapConstants.SNAPLEN_UNLIMITED && capturedLength > snapLen )
		{
			throw new PcapException( "captured packet size exceeds interface snaplen (snaplen=%d, captured=%d)", 
			                         snapLen, 
			                         capturedLength );
		}
			
		byte[] content = new byte[capturedLength];
		slaveStream.readFully( content );

		return new EnhancedPacketBlock( this.fakeIface, 
		                                timestamp, 
		                                originalLength, 
		                                content,
		                                new ArrayList<>() );
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////// IPcapParser Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	@Override
	public IPcapBlock nextBlock() throws IOException, PcapException
	{
		switch( this.state )
		{
			case GenerateFakeShb:
				readHeader();
				state = State.GenerateFakeIdb;
				return this.fakeSectionHeader;
			case GenerateFakeIdb:
				state = State.Content;
				return this.fakeIface;
			case Content:
				return readNextPacket();
				
			default:
				// Should never get here
				throw new IllegalStateException();
		}
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	protected static boolean isTcpDumpHeader( byte[] idBlock )
	{
		if( idBlock.length < 1 )
			throw new IllegalArgumentException( "idBlock must be at least 1 byte long" );
		
		int uint8at0 = idBlock[0] & 0xFF;
		return uint8at0 == 0xA1 || uint8at0 == 0xD4 || uint8at0 == 0x4D; 
	}
}
