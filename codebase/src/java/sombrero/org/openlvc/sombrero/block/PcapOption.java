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

import java.io.IOException;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.openlvc.sombrero.io.Endianness;
import org.openlvc.sombrero.io.PcapInputStream;

/**
 * Optional field value that can be stored against a {@link IPcapBlock}
 * <p/>
 * Values are stored in opque binary form as they were specified in the file, but can be interpreted
 * through the helper methods provided.
 * 
 * @see #getNumberValue()
 * @see #getStringValue()
 */
public record PcapOption( int id, Endianness endianness, byte[] value )
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

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	@Override
	public int hashCode()
	{
		final Integer PRIME = 31;
		Integer result = 1;
		result = PRIME * result + this.id;
		result = PRIME * result + Arrays.hashCode( this.value );
		return result;
	}
	
	@Override
	public boolean equals( Object other )
	{
		if( this == other )
			return true;
		
		if( other instanceof PcapOption otherOption )
		{
			if( this.id != otherOption.id )
				return false;
			
			return Arrays.equals( this.value, otherOption.value );
		}
		else
		{
			return false;
		}
	}
	
	@Override
	public String toString()
	{
		return "id="+this.id+", value="+this.value;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return this option's value interpreted as a number
	 */
	public Number getNumberValue()
	{
		byte[] temp = this.value;
		if( this.endianness == Endianness.Little )
		{
			temp = Arrays.copyOf( this.value, value.length );
			for( int i = 0 ; i < temp.length / 2 ; ++i )
			{
				byte bucket = temp[i];
				temp[i] = temp[temp.length - 1 - i];
				temp[temp.length - 1 - i] = bucket;
			}
		}
		
		return new BigInteger( temp );
	}
	
	/**
	 * Returns this value interpreted as a PcapNG time stamp.
	 * <p/>
	 * PcapNG time stamps are always specified relative to an offset, which is to be provided in the
	 * <code>offset<code> parameter.
	 * <p/>
	 * Note: This method requires a 8 byte option value to interpret the time stamp correctly. If
	 * the value array contains less than 8 bytes an {@link IllegalStateException} will be thrown 
	 * 
	 * @param offset the offset that the time value is relative to
	 * @param resolution the units that the time units are measured in
	 * @return this option's value, interpreted as a time stamp
	 * 
	 * @throws IllegalStateException if the value does not have 8-bytes to read the time stamp from 
	 */
	public Instant getTimestampValue( Instant offset, ChronoUnit resolution )
	{
		if( this.value.length < 8 )
			throw new IllegalStateException( "not a timestamp value (size="+this.value.length+")" );
		
		try( PcapInputStream stream = PcapInputStream.create(this.value, this.endianness) )
		{
			
			long timestampUpper = stream.readUint32();
			long timestampLower = stream.readUint32();
			long timeUnits = timestampUpper << 32 | timestampLower;
			return offset.plus( Duration.of(timeUnits, resolution) );
		}
		catch( IOException ioe )
		{
			// This should never be thrown as we bounds check above 
			throw new IllegalStateException( ioe );
		}
	}
	
	/**
	 * @return this option's value interpreted as a string
	 */
	public String getStringValue()
	{
		return new String( this.value );
	}

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	/**
	 * Returns the first option found in the collection that matches the specified id
	 * 
	 * @param options the collection of options to search through
	 * @param id the id of the option to find
	 * @return an {@link Optional} containing the desired option if it was found in the collection
	 */
	public static Optional<PcapOption> getOption( Collection<PcapOption> options, int id )
	{
		return options.stream().filter( o -> o.id() == id ).findFirst();
	}
}
