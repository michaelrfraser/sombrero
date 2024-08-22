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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

/**
 * Specialized form of input stream that can read unsigned integer values.
 * <p/>
 * This class is abstract and cannot be instantiated directly, however static factory methods are 
 * provided to construct a child implementation depending on a specified {@link Endianness}.
 */
public abstract class PcapInputStream extends DataInputStream
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
	protected PcapInputStream( InputStream in )
	{
		super( in );
	}
	
	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * @return the byte order that this stream will use to interpret data values
	 */
	public abstract Endianness getEndianness();
	
	/**
	 * Reads the next byte in the stream and returns its value as an unsigned 8-bit integer
	 * 
	 * @return the value of the next byte in the stream, interpreted as an unsigned 8-bit integer
	 * @throws EOFException if this input stream has reached the end.
     * @throws IOException the stream has been closed and the contained input stream does not 
     *                     support reading after close, or another I/O error occurs.
	 */
	public int readUint8() throws IOException
	{
		return in.read() & 0xFF;
	}
	
	/**
	 * Reads the next two bytes in the stream and returns the value as an unsigned 16-bit integer
	 * 
	 * @return the value of the next two bytes in the stream, interpreted as an unsigned 16-bit 
	 *         integer
	 * @throws EOFException if this input stream reaches the end before reading two bytes.
     * @throws IOException the stream has been closed and the contained input stream does not 
     *                     support reading after close, or another I/O error occurs.
	 */
	public abstract int readUint16() throws IOException;
	
	/**
	 * Reads the next four bytes in the stream and returns the value as an unsigned 32-bit integer
	 * 
	 * @return the value of the next four bytes in the stream, interpreted as an unsigned 32-bit 
	 *         integer
	 * @throws EOFException if this input stream reaches the end before reading four bytes.
     * @throws IOException the stream has been closed and the contained input stream does not 
     *                     support reading after close, or another I/O error occurs.
	 */
	public abstract long readUint32() throws IOException;
	
	/**
	 * Reads the next eight bytes in the stream and returns the value as an unsigned 64-bit integer
	 * 
	 * @return the value of the next eight bytes in the stream, interpreted as an unsigned 64-bit 
	 *         integer
	 * @throws EOFException if this input stream reaches the end before reading eight bytes.
     * @throws IOException the stream has been closed and the contained input stream does not 
     *                     support reading after close, or another I/O error occurs.
	 */
	public abstract BigInteger readUint64() throws IOException;
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	/**
	 * Creates a {@link PcapInputStream} to read data from the specified byte array, interpreted 
	 * using the specified {@link Endianness}
	 * 
	 * @param data the byte array to read from
	 * @param endianess the {@link Endianness} that the data contained in the byte array is encoded 
	 *                  in
	 * @return a {@link PcapInputStream} to read data from the specified array
	 */
	public static PcapInputStream create( byte[] data, Endianness endianess )
	{
		ByteArrayInputStream in = new ByteArrayInputStream( data );
		if( endianess == Endianness.Big )
			return new PcapInputStreamBE( in );
		else
			return new PcapInputStreamLE( in );
	}
	
	/**
	 * Creates a {@link PcapInputStream} to read data from a generic {@link InputStream}, 
	 * interpreted using the specified {@link Endianness}
	 * 
	 * @param in the underlying {@link InputStream} 
	 * @param endianess the {@link Endianness} that the data contained within stream is encoded in
	 * @return a {@link PcapInputStream} to read data from the specified stream
	 */
	public static PcapInputStream create( InputStream in, Endianness endianess )
	{
		if( endianess == Endianness.Big )
			return new PcapInputStreamBE( in );
		else
			return new PcapInputStreamLE( in );
	}
}
