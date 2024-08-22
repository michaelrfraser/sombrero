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
package org.openlvc.sombrero.interpreter;

/**
 * Abstract data type for conveying a layer within a network protocol stack.
 * <p/>
 * Each layer contains a reference to its parent layer within the protocol stack. The direct parent
 * can be queried through {@link #getParent()}, or you can use {@link #findParent(Class)} to search
 * up the stack to find a particular parent layer. A top-level layer (e.g. Ethernet) will have no 
 * parent, in which case the parent field will be <code>null</code>. 
 * <p/>
 * The layer's data payload can be queried through the {@link #getData()} method.
 */
public abstract class ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private ProtocolLayer parent;
	private byte[] data;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * ProtocolLayer constructor for child layers.
	 * 
	 * @param parent the parent layer in the stack
	 * @param data the layer's data payload
	 */
	protected ProtocolLayer( ProtocolLayer parent, byte[] data )
	{
		this.parent = parent;
		this.data = data;
	}
	
	/**
	 * ProtocolLayer constructor for top-level layers (e.g. Ethernet)
	 * 
	 * @param data the layer's data payload
	 */
	protected ProtocolLayer( byte[] data )
	{
		this( null, data );
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Searches this layer's ancestry for a parent of the specified type
	 * @param <T> The type of layer to search for
	 * @param layerClass The class of the layer to search for
	 * @return the first parent layer encountered of the specified type, or <code>null</code> if
	 *         no such layer could be found 
	 */
	public <T extends ProtocolLayer> T findParent( Class<T> layerClass )
	{
		if( parent == null )
			return null;
		else if( parent.getClass().equals(layerClass) )
			return layerClass.cast( parent );
		else
			return parent.findParent( layerClass );
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return this layer's immediate parent in the protocol stack
	 */
	public ProtocolLayer getParent()
	{
		return this.parent;
	}
	
	/**
	 * @return this layer's data payload
	 */
	public byte[] getData()
	{
		return this.data;
	}

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
