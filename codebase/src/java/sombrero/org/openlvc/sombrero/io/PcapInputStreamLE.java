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
package org.openlvc.sombrero.io;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

/**
 * A {@link PcapInputStream} implementation for reading Little-Endian byte ordered data
 */
public class PcapInputStreamLE extends PcapInputStream
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	public PcapInputStreamLE( InputStream in )
	{
		super( in );
	}
	
	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	
	////////////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////// PcapInputStream Methods /////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return {@link Endianness#Little} indicating this stream interprets data with Little-Endian
	 *         byte ordering
	 */
	@Override
	public Endianness getEndianness()
	{
		return Endianness.Little;
	}
	
	@Override
	public int readUint16() throws IOException
	{
		// Get the next 2 bytes from the stream
		int ch1 = in.read();
		int ch2 = in.read();
		
		// Assemble the value and return
		return (ch2 << 8 | ch1) & 0xFFFF;
	}
	
	@Override
	public long readUint32() throws IOException
	{
		// Get the next 4 bytes from the stream
		int ch1 = in.read();
		int ch2 = in.read();
		int ch3 = in.read();
		int ch4 = in.read();

		// Check that we haven't gone beyond the stream bounds
		if( (ch1 | ch2 | ch3 | ch4) < 0 )
			throw new EOFException();

		// Assemble the value and return
		return (ch4 << 24 | ch3 << 16 | ch2 << 8 | ch1) & 0xFFFFFFFFL;
	}

	@Override
	public BigInteger readUint64() throws IOException
	{
		byte[] raw = in.readNBytes( 8 );
		for( int i = 0 ; i < raw.length / 2 ; ++i )
		{
			byte temp = raw[i];
			raw[i] = raw[raw.length - 1 - i];
			raw[raw.length - 1 - i] = temp;
		}
		
		return new BigInteger( raw );
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
