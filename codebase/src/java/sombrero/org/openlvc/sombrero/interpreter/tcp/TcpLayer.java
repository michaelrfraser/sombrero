/*
 *   Copyright 2025 Open LVC Project.
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
package org.openlvc.sombrero.interpreter.tcp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.openlvc.sombrero.interpreter.ProtocolLayer;

/**
 * Represents Transmission Control Protocol information defined within a network packet
 */
public class TcpLayer extends ProtocolLayer
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private int sourcePort;
	private int destPort;
	private long seqNumber;
	private long ackNumber;
	private int flags;
	private int window;
	private int checksum;
	private int urgentPointer;
	private List<TcpOption> options;
	
	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	/**
	 * Constructor for TcpLayer with specified values
	 * 
	 * @param parent the parent layer in the protocol stack (usually IPv4 or IPv6)
	 * @param sourcePort the sender's port number
	 * @param destPort the receiver's port number
	 * @param seqNumber the TCP packet's sequence number
	 * @param ackNumber the TCP packet's acknowledgment number
	 * @param flags the TCP packet's flags
	 * @param window the sender's receive window
	 * @param checksum the TCP packet's checksum
	 * @param urgentPointer offset to the last urgent data byte if the URG flag is set
	 * @param options the TCP options that have been sent with the TCP packet
	 * @param data the TCP packet's data payload
	 */
	public TcpLayer( ProtocolLayer parent, 
	                 int sourcePort, 
	                 int destPort, 
	                 long seqNumber, 
	                 long ackNumber,
	                 int flags, 
	                 int window, 
	                 int checksum, 
	                 int urgentPointer, 
	                 Collection<TcpOption> options,
	                 byte[] data ) 
	{
		super( parent, data );
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		this.seqNumber = seqNumber;
		this.ackNumber = ackNumber;
		this.flags = flags;
		this.window = window;
		this.checksum = checksum;
		this.options = new ArrayList<>( options );
		this.urgentPointer = urgentPointer;
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	@Override
	public String toString()
	{
		// Construct a comma delimited list of all flags
		List<String> presentFlags = new ArrayList<String>();
		if( this.isFlagCwr() ) presentFlags.add( "CWR" );
		if( this.isFlagEce() ) presentFlags.add( "ECE" );
		if( this.isFlagUrg() ) presentFlags.add( "URG" );
		if( this.isFlagAck() ) presentFlags.add( "ACK" );
		if( this.isFlagPsh() ) presentFlags.add( "PSH" );
		if( this.isFlagRst() ) presentFlags.add( "RST" );
		if( this.isFlagSyn() ) presentFlags.add( "SYN" );
		if( this.isFlagFin() ) presentFlags.add( "FIN" );
		
		String flagsString = String.join( ",", presentFlags );
		
		// Return formatted info string
		return String.format( "TCP: %d -> %d [%s] Seq=%d Ack=%d Win=%d Len=%d", 
		                      this.sourcePort,
		                      this.destPort,
		                      flagsString,
		                      this.seqNumber,
		                      this.ackNumber,
		                      this.window,
		                      this.getData().length);
	}
	
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * @return the sender's port number
	 */
	public int getSourcePort()
	{
		return this.sourcePort;
	}
	
	/**
	 * @return the receiver's port number
	 */
	public int getDestPort()
	{
		return this.destPort;
	}

	/**
	 * Returns this TCP packet's sequence number.
	 * <p/>
	 * The sequence number Has a dual role:
	 * <ul>
	 *  <li>
	 *    If the SYN flag is set (1), then this is the initial sequence number. The sequence 
	 *    number of the actual first data byte and the acknowledged number in the corresponding 
	 *    ACK are then this sequence number plus 1.
	 *  </li>
	 *  <li>
	 *    If the SYN flag is unset (0), then this is the accumulated sequence number of the first 
	 *    data byte of this segment for the current session.
	 *  </li>
	 * </ul>
	 * @return this TCP packet's sequence number
	 * 
	 * @see #isFlagSyn()
	 * @see #getAckNumber()
	 */
	public long getSeqNumber()
	{
		return seqNumber;
	}

	/**
	 * Returns this TCP packet's acknowledgement number.
	 * <p/>
	 * If the ACK flag is set then the value of this field is the next sequence number that the 
	 * sender of the ACK is expecting. This acknowledges receipt of all prior bytes (if any). The 
	 * first ACK sent by each end acknowledges the other end's initial sequence number itself, 
	 * but no data.
	 *  
	 * @return this TCP packet's acknowledgement number
	 * 
	 * @see #isFlagAck()
	 */
	public long getAckNumber()
	{
		return ackNumber;
	}
	
	/**
	 * Returns this TCP packet's flags in a bit array
	 * <p/>
	 * Bit masks for each of the flags are specified in {@link TcpConstants}
	 * 
	 * @return this TCP packet's flags in a bit array
	 * 
	 * @see TcpConstants
	 */
	public int getFlags()
	{
		return flags;
	}

	/**
	 * @return whether the Congestion Window Reduced (CWR) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_CWR_MASK
	 */
	public boolean isFlagCwr()
	{
		return (this.flags & TcpConstants.TCP_FLAG_CWR_MASK) != 0;
	}
	
	/**
	 * @return whether the ECN-Echo (ECE) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_ECE_MASK
	 */
	public boolean isFlagEce()
	{
		return (this.flags & TcpConstants.TCP_FLAG_ECE_MASK) != 0;
	}
	
	/**
	 * @return whether the Urgent Pointer Field Significant (URG) field is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see #getUrgentPointer()
	 * @see TcpConstants#TCP_FLAG_URG_MASK
	 */
	public boolean isFlagUrg()
	{
		return (this.flags & TcpConstants.TCP_FLAG_URG_MASK) != 0;
	}
	
	/**
	 * @return whether the Acknowledgement Field Significant (ACK) field is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see #getAckNumber()
	 * @see TcpConstants#TCP_FLAG_ACK_MASK
	 */
	public boolean isFlagAck()
	{
		return (this.flags & TcpConstants.TCP_FLAG_ACK_MASK) != 0;
	}
	
	/**
	 * @return whether the Push Function (PSH) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_PSH_MASK
	 */
	public boolean isFlagPsh()
	{
		return (this.flags & TcpConstants.TCP_FLAG_PSH_MASK) != 0;
	}
	
	/**
	 * @return whether the Reset Connection (RST) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_RST_MASK
	 */
	public boolean isFlagRst()
	{
		return (this.flags & TcpConstants.TCP_FLAG_RST_MASK) != 0;
	}
	
	/**
	 * @return whether the Synchronize Acknowledgement Numbers (SYN) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_SYN_MASK
	 */
	public boolean isFlagSyn()
	{
		return (this.flags & TcpConstants.TCP_FLAG_SYN_MASK) != 0;
	}
	
	/**
	 * @return whether the Last Packet from Sender (FIN) flag is set on this TCP packet
	 * 
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_FIN_MASK
	 */
	public boolean isFlagFin()
	{
		return (this.flags & TcpConstants.TCP_FLAG_FIN_MASK) != 0;
	}
	
	
	/**
	 * @return the number of window size units that the sender is willing to receive
	 */
	public int getWindow()
	{
		return window;
	}

	/**
	 * If the <code>URG</code> flag is set, then this 16-bit field is an offset from the sequence number 
	 * indicating the last urgent data byte.
	 * 
	 * @return the offset of the last urgent data byte
	 * 
	 * @see #isFlagUrg()
	 * @see #getFlags()
	 * @see TcpConstants#TCP_FLAG_URG_MASK
	 */
	public int getUrgentPointer()
	{
		return urgentPointer;
	}
	
	/**
	 * @return the packet's TCP level checksum
	 */
	public int getChecksum()
	{
		return this.checksum;
	}
	
	/**
	 * @return the option structures that were present in the TCP packet's <code>Options</code> 
	 *         section
	 *         
	 * @see TcpOption
	 */
	public Collection<TcpOption> getOptions()
	{
		return new ArrayList<TcpOption>( this.options );
	}
	
	/**
	 * @return whether any option structures were present in this TCP packet
	 */
	public boolean hasOptions()
	{
		return !this.options.isEmpty();
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
