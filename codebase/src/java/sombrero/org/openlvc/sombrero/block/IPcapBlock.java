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
 * Marker interface for an information block within a pcap capture file.
 * <p/>
 * The {@link #getType()} method can be called to query the specific type of the block as it was
 * stored in the pcapng file.
 * <p/>
 * See section 3.2 of the pcapng specification for a list of valid block types. 
 */
public interface IPcapBlock
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/** 
	 * @return a unique unsigned value that identifies the block.
	 */
	public long getType();
}
