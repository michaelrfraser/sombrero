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

/**
 * Represents a pcapng block that we don't support/know how to parse.
 * <p/>
 * The block's data payload can be queried through {@link #getContent()} 
 */
public class UnsupportedBlock implements IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private long type;
	private byte[] content;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for UnsupportedBlock with specified values
	 * 
	 * @param type the block's type
	 * @param content the block's unparsed data
	 */
	public UnsupportedBlock( long type, byte[] content )
	{
		this.type = type;
		this.content = content;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// IPcapBlock Interface Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	@Override
	public long getType()
	{
		return this.type;
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the binary content of this block's data payload
	 */
	public byte[] getContent()
	{
		return this.content;
	}

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
