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

import org.openlvc.sombrero.PcapException;
import org.openlvc.sombrero.block.IPcapBlock;

/**
 * An interface through which {@link IPcapBlock} instances can be read.
 * <p/>
 * The helper factory method {@link #createFor(InputStream)} is provided to construct an appropriate
 * implementation based on the contents of an input stream provided. 
 */
public interface IPcapReader
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Reads and returns the next block in sequence from the current source
	 *  
	 * @return an {@link IPcapBlock} representing the next block in sequence from the current
	 *         source, or <code>null</code> if there are no more blocks to read
	 * @throws IOException if an error occurred reading from the current source
	 * @throws PcapException if there was an error interpreting PCAP content being read
	 */
	public IPcapBlock nextBlock() throws IOException, PcapException;
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	/**
	 * Factory method to create an {@link IPcapReader} implementation to read from the specified
	 * {@link InputStream}.
	 * <p/>
	 * The start of the stream is initially inspected to decide what version of the pcap standard
	 * the stream's content conforms to. An appropriate reader is created accordingly
	 * 
	 * @param in the stream to read PCAP content from
	 * @return an {@link IPcapReader} implementation to read content from the stream
	 * @throws IOException if an error occurred reading from the stream
	 * @throws PcapException if there was an error interpreting PCAP content from the stream
	 */
	public static IPcapReader createFor( InputStream in ) throws IOException, PcapException
	{
		BufferedInputStream bis = new BufferedInputStream( in );
		
		// Read first four bytes of the stream to identify whether we're TcpDump or PcapNG
		bis.mark( 4 );
		byte[] header = bis.readNBytes( 4 );
		bis.reset();
		
		if( TcpDumpReader.isTcpDumpHeader(header) )
			return new TcpDumpReader( bis );
		else if( PcapNgReader.isPcapNgHeader(header) )
			return new PcapNgReader( bis );
		else
			throw new PcapException( "Not a PCAP file (could not understand header block)" );
	}
}
