/*
 *   Copyright 2024 Calytrix Technologies
 *
 *   This file is part of sombrero.
 *
 *   NOTICE:  All information contained herein is, and remains
 *            the property of Calytrix Technologies Pty Ltd.
 *            The intellectual and technical concepts contained
 *            herein are proprietary to Calytrix Technologies Pty Ltd.
 *            Dissemination of this information or reproduction of
 *            this material is strictly forbidden unless prior written
 *            permission is obtained from Calytrix Technologies Pty Ltd.
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 */
package org.openlvc.sombrero.interpreter.ip;

import java.util.ArrayList;
import java.util.Collection;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Utility class for reassembling a data payload that is split over multiple packets using
 * IPv4's fragmentation mechanism.
 * <p/>
 * A {@link Ip4FragmentSequence} must be constructed with the sequence identifier it will manage.
 * The sequence identifier can be obtained from the IP layer data by calling 
 * {@link Ip4Layer#getIdentification()}.
 * <p/>
 * As packets are received for the sequence, they should be added by calling 
 * {@link #addFragment(Ip4Layer)}.
 * <p/>
 * Once all packets in the sequence have been added call {@link #reassemble()} to obtain the 
 * reassembled sequence data payload.  
 */
public class Ip4FragmentSequence
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int identifier;
	private SortedSet<Ip4Layer> fragments;
	private boolean complete;
	private boolean completeDirty;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Ip4FragmentSequence constructor with specified sequence identifier
	 * 
	 * @param identifier
	 */
	public Ip4FragmentSequence( int identifier )
	{
		this.identifier = identifier;
		this.fragments = new TreeSet<>( Ip4FragmentSequence::compareFragments );
		this.complete = false;
		this.completeDirty = false;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Returns the reassembled data payload of this fragment sequence.
	 * <p/>
	 * Note: All packets in the sequence must have been added via the {@link #addFragment(Ip4Layer)}
	 * method before calling this function.
	 * 
	 * @return the reassembled data payload of this fragment sequence
	 * @throw {@link IllegalStateException} if this sequence is missing fragments
	 * 
	 * @see #isComplete()
	 * @see #addFragment(Ip4Layer)
	 */
	public byte[] reassemble()
	{
		if( !isComplete() )
			throw new IllegalStateException( "incomplete sequence" );
		
		Ip4Layer lastFragment = this.fragments.getLast();
		
		int reassembledSize =   lastFragment.getFragmentOffset() * 8 
		                      + lastFragment.getData().length;
		byte[] data = new byte[reassembledSize];
		for( Ip4Layer fragment : this.fragments )
		{
			byte[] fragmentData = fragment.getData();
			System.arraycopy( fragmentData, 
			                  0, 
			                  data, 
			                  fragment.getFragmentOffset() * 8, 
			                  fragmentData.length );
		}
		
		return data;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * Adds data contained in an {@link Ip4Layer} that is marked as a fragment of this sequence
	 * 
	 * @param fragment the fragment to add to this sequence
	 * @throws IllegalArgumentException if the fragment does not belong to this sequence
	 */
	public void addFragment( Ip4Layer fragment )
	{
		if( fragment.getIdentification() != this.identifier )
			throw new IllegalArgumentException( "fragment does not belong to this sequence" );
		
		this.fragments.add( fragment );
		this.completeDirty = true;
	}
	
	/**
	 * @return the collection of fragments that have been collected for this sequence so far
	 */
	public Collection<Ip4Layer> getFragments()
	{
		return new ArrayList<>( this.fragments );
	}
	
	/**
	 * @return <code>true</code> if all fragments have been collected for this sequence, otherwise
	 *         <code>false</code> if the sequence is still missing fragments
	 */
	public boolean isComplete()
	{
		if( this.completeDirty )
		{
			int expectedOffset = 0;
			int fragmentCount = this.fragments.size();
			boolean fragmentsValid = true;
			int index = 0;
			for( Ip4Layer fragment : this.fragments )
			{
				// Ensure this fragment's offset matches what we expect it to be. If not, we are
				// missing a fragment in the sequence
				if( fragment.getFragmentOffset() != expectedOffset )
					fragmentsValid = false;
				
				// If this is the last fragment we have on record, then ensure that the More 
				// Fragments flag is not set
				if( index == fragmentCount - 1 && fragment.isMoreFragments() )
					fragmentsValid = false;

				// Calculate the next fragment's expected offset based on the current fragment's 
				// data size 
				if( fragmentsValid )
					expectedOffset += fragment.getData().length / 8;
				else
					break;
				
				++index;
			}
			
			this.complete = fragmentsValid;
			this.completeDirty = false;
		}
		
		return this.complete;
	}

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	/*
	 * Private comparator function to order based on fragment offset
	 */
	private static int compareFragments( Ip4Layer a, Ip4Layer b )
	{
		return a.getFragmentOffset() - b.getFragmentOffset();
	}
}
