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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class for managing data fragmentation over multiple IPv4 frames.
 * <p/>
 * For each IPv4 frame received, call {@link #processFrame(Ip4Layer)}. A {@link SequenceResult} 
 * will be returned indicating whether enough data has been received to pass onto the next layer in 
 * the stack. 
 * <p/>
 * If the frame is part of a fragmented sequence that is still incomplete, the manager will hold 
 * onto the frame to resolve the sequence during a future call of {@link #processFrame(Ip4Layer)}.  
 * <p/>
 * In order to prevent sequence data from accumulating over time, a time-to-live value is held for 
 * each sequence. Call {@link #tickTtl()} to increment the ttl counter and remove any stale records.
 */
public class Ip4FragmentManager
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	public static final int DEFAULT_TTL = 255;

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private Map<Integer,SequenceHolder> sequences;
	private int fragmentSequenceTtl;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	public Ip4FragmentManager()
	{
		this.sequences = new HashMap<>();
		this.fragmentSequenceTtl = DEFAULT_TTL;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Processes a single {@link Ip4Layer} frame, resolving it to an outstanding fragmentation 
	 * sequence, and returning whether that sequence is now complete.
	 *  
	 * @param layer the frame to process
	 * @return an {@link SequenceResult} indicating whether the fragmentation sequence is now
	 *         complete, and if so, containing the sequence's fragments and reassembled data 
	 */
	public SequenceResult processFrame( Ip4Layer layer )
	{
		SequenceResult result = SequenceResult.IncompleteResult;
		if( layer.isPartOfFragmentSequence() )
		{
			// Find the tracker for this sequence, or create a new tracker if
			// it doesn't already exist
			int fragmentId = layer.getIdentification();
			SequenceHolder holder = this.sequences
			                            .computeIfAbsent( fragmentId, 
			                                              SequenceHolder::new );
			holder.sequence.addFragment( layer );
			if( !layer.isMoreFragments() )
			{
				// Remote side has advised us that there are no more fragments in this
				// sequence, so we can free up the tracker
				this.sequences.remove( fragmentId );
				
				// Check to see if all fragments were received for this sequence. 
				if( holder.sequence.isComplete() )
					result = SequenceResult.sequenceResult( holder.sequence );
			}
		}
		else
		{
			// Not part of a fragment sequence so we can just pass it through
			result = SequenceResult.standaloneResult( layer );
		}
		
		return result;
	}
	
	/**
	 * Decrements the time-to-live counter of all outstanding sequences, and removes those that
	 * are stale 
	 */
	public void tickTtl()
	{
		// Note: These two steps could potentially be combined into one call to removeIf(), however
		// mutating a value in removeIf() doesn't seem quite right... 
		
		// Decrement ttl value of all current sequences
		this.sequences.values().forEach( holder -> --holder.ttl );
		
		// Remove any stale sequences
		this.sequences.values().removeIf( holder -> holder.ttl < 1 );
	}

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	public int getFragmentSequenceTtl()
	{
		return this.fragmentSequenceTtl;
	}
	
	public void setFragmentSequenceTtl( int ttl )
	{
		this.fragmentSequenceTtl = ttl;
		
		// Clamp any existing ttl values that are greater than the one just set
		this.sequences.values().forEach( holder -> holder.ttl = Math.max(holder.ttl, ttl) );
	}

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	private class SequenceHolder
	{
		private Ip4FragmentSequence sequence;
		private int ttl;
		
		public SequenceHolder( int identifier )
		{
			this.sequence = new Ip4FragmentSequence( identifier );
			this.ttl = fragmentSequenceTtl;
		}
	}
	
	/**
	 * Compound result value for the return value of {@link #processFrame(Ip4Layer)}
	 * <p/>
	 * The method {@link #isComplete()} indicates whether all fragments in the sequence have been
	 * received. If the return value is <code>true</code> then the re-assembled data payload can
	 * be obtained by calling {@link #getPayload()}.
	 */
	public static class SequenceResult
	{
		protected static final SequenceResult IncompleteResult 
			= new SequenceResult( false, Collections.emptyList(), new byte[0] );
		
		private boolean complete;
		private Collection<Ip4Layer> fragments;
		private byte[] payload;
		
		private SequenceResult( boolean complete, Collection<Ip4Layer> fragments, byte[] payload )
		{
			this.complete = complete;
			this.fragments = fragments;
			this.payload = payload;
		}
		
		/**
		 * @return <code>true</code> if all frames have been received in the fragmentation sequence
		 */
		public boolean isComplete()
		{
			return this.complete;
		}
		
		/**
		 * @return the ordered collection of frames in the fragmentation sequence
		 */
		public Collection<Ip4Layer> getFragments()
		{
			return new ArrayList<>( this.fragments );
		}
		
		/**
		 * @return the re-assembled data payload for this sequence
		 */
		public byte[] getPayload()
		{
			return this.payload;
		}
		
		protected static SequenceResult standaloneResult( Ip4Layer layer )
		{
			return new SequenceResult( true, Collections.singleton(layer), layer.getData() );
		}
		
		protected static SequenceResult sequenceResult( Ip4FragmentSequence sequence )
		{
			return new SequenceResult( true, sequence.getFragments(), sequence.reassemble() );
		}
	}
}
