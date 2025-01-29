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

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.openlvc.sombrero.PcapConstants;
import org.openlvc.sombrero.block.EnhancedPacketBlock;
import org.openlvc.sombrero.interpreter.ip.Ip4Layer;
import org.openlvc.sombrero.interpreter.ip.IpConstants;
import org.openlvc.sombrero.interpreter.arp.ArpLayer;
import org.openlvc.sombrero.interpreter.ethernet.EthernetConstants;
import org.openlvc.sombrero.interpreter.ethernet.EthernetLayer;
import org.openlvc.sombrero.interpreter.ip.Ip4FragmentManager;
import org.openlvc.sombrero.interpreter.tcp.TcpConstants;
import org.openlvc.sombrero.interpreter.tcp.TcpLayer;
import org.openlvc.sombrero.interpreter.tcp.TcpOption;
import org.openlvc.sombrero.interpreter.udp.UdpLayer;
import org.openlvc.sombrero.io.Endianness;
import org.openlvc.sombrero.io.PcapInputStream;

/**
 * An interpreter that processes the contents of an {@link EnhancedPacketBlock}.
 * <p/>
 * The interpreter uses the {@link Consumer} pattern to report back protocol layers discovered as
 * it processes a packet. You can register a consumer for a protocol layer by calling its 
 * appropriate <code>on</code> method (e.g. {@link #onIp4(Consumer)}, {@link #onUdp(Consumer)}.
 * <p/>
 * To process a packet, call {@link #process(EnhancedPacketBlock)}. Registered consumers will be
 * called as appropriate protocol layers are discovered within the packet.
 */
public class PacketInterpreter
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------
	private Consumer<PacketLayer>              packetConsumer;
	private Consumer<EthernetLayer>            ethernetConsumer;
	private Consumer<RawLayer>                 rawConsumer;
	private Consumer<ArpLayer>                 arpConsumer;
	private Consumer<Ip4Layer>                 ip4Consumer;
	private Consumer<UdpLayer>                 udpConsumer;
	private Consumer<TcpLayer>                 tcpConsumer;
	
	private Ip4FragmentManager                 ipFragmentManager;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	public PacketInterpreter()
	{
		this.ipFragmentManager = new Ip4FragmentManager();
	}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Processes the contents of an {@link EnhancedPacketBlock}, notifying registered consumers
	 * as corresponding protocol layers are found.
	 * <p/>
	 * The in-most protocol layer that the interpreter could successfully interpret will be returned.
	 * 
	 * @param packet the packet to process
	 * @return the in-most protocol layer contained within the packet that the interpreter could
	 *         understand
	 * @throws IOException if there was an error reading the contents of the packet
	 * @throws IllegalArgumentException if the packet was captured from an unsupported link type
	 */
	public ProtocolLayer process( EnhancedPacketBlock packet ) throws IOException
	{
		PacketLayer me = new PacketLayer( packet );
		if( this.packetConsumer != null )
			this.packetConsumer.accept( me );
		
		byte[] packetData = packet.getPacketData();
		
		// Ignore truncated packets
		if( packet.isTruncated() )
			return me;
		
		ProtocolLayer deepestLayer = me;
		switch( packet.getInterface().getLinkType() )
		{
			case PcapConstants.LINKTYPE_NULL, PcapConstants.LINKTYPE_ETHERNET:
				deepestLayer = processEthernet( me, packetData );
				break;
			
			case PcapConstants.LINKTYPE_RAW:
				deepestLayer = processRaw( me, packetData );
				break;
			
			// Still unsure whether this should either be ignored, or reported back through an
			// unknown link layer consumer. Leaving as exception for now so the behavior is
			// explicit
			default:
				throw new IllegalArgumentException( "unsupported link type "+packet.getInterface().getLinkType() );
		}
		
		// Keep the TTL of outstanding IP4 Fragment sequences ticking along so we're not holding
		// out-date sequences forever
		this.ipFragmentManager.tickTtl();
		
		return deepestLayer;
	}

	/**
	 * Interprets binary data as a raw ethernet frame.
	 * <p/>
	 * This method will notify the registered ethernet consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param parent the parent {@link ProtocolLayer} that contains the ethernet layer
	 * @param data the ethernet data in binary form
	 * @return the in-most layer within this ethernet packet that the interpreter could understand
	 * @throws IOException if there was an error reading the ethernet data
	 * 
	 * @see #onEthernet(Consumer)
	 */
	private ProtocolLayer processEthernet( ProtocolLayer parent, byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			byte[] destination = in.readNBytes( 6 ); // Destination MAC Address
			byte[] source = in.readNBytes( 6 );      // Source MAC Address
			int type = in.readUint16();
			byte[] payloadBytes = Arrays.copyOfRange( data, 14, data.length );

			// Notify ethernet consumer
			EthernetLayer me = new EthernetLayer( parent, 
			                                      destination, 
			                                      source, 
			                                      type, 
			                                      payloadBytes );
			if( ethernetConsumer != null )
				ethernetConsumer.accept( me );

			ProtocolLayer inmostLayer = me;
			
			// Find processor for next level 
			if( type == EthernetConstants.ETHERTYPE_IP4 )
				inmostLayer = processIPv4( me, payloadBytes );
			
			return inmostLayer;
		}
	}
	
	/**
	 * Interprets binary data as a raw IP frame.
	 * <p/>
	 * This method will notify the registered raw consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param parent the parent {@link ProtocolLayer} that contains the Raw layer
	 * @param data the raw IP data in binary form
	 * @return the in-most layer within this ethernet packet that the interpreter could understand
	 * @throws IOException if there was an error reading the raw IP data
	 * 
	 * @see #onRawFrame(Consumer)
	 */
	private ProtocolLayer processRaw( ProtocolLayer parent, byte[] data ) throws IOException
	{
		// Notify raw frame consumer
		RawLayer me = new RawLayer( parent, data );
		if( rawConsumer != null )
			rawConsumer.accept( me );
		
		ProtocolLayer inmostLayer = me;
		
		if( data.length < 4 )
			return me;
		
		// Find processor for next level by peeking version byte to determine route
		int version = data[0] >> 4;
		if( version == 4 )
			inmostLayer = processIPv4( me, data );
		
		return inmostLayer;
	}
	
	/**
	 * Interprets binary data as an IPv4 frame.
	 * <p/>
	 * This method will notify the registered IPv4 consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param parent the {@link ProtocolLayer} that contains this IPv4 layer
	 * @param data the IPv4 data in binary form
	 * @return the in-most layer within this IPv4 packet that the interpreter could understand
	 * @throws IOException if there was an error reading the IPv4 data
	 * 
	 * @see #onIp4(Consumer)
	 */
	private ProtocolLayer processIPv4( ProtocolLayer parent, byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			int firstOct = in.readUint8();
			int ihl = firstOct & 0x0F;
			
			int tos = in.readUint8();
			int totalLength = in.readUint16();
			
			// If total length of zero is presumed to be because of TCP Segmentation Offload
			// Just use the data length instead
			if( totalLength == 0 )
				totalLength = data.length;
			
			int identification = in.readUint16();
			int flagsAndOffset = in.readUint16();
			int ttl = in.readUint8();
			int proto = in.readUint8();
			int checksum = in.readUint16();
			
			InetAddress sourceAddr = InetAddress.getByAddress( in.readNBytes(4) );
			InetAddress destAddr = InetAddress.getByAddress( in.readNBytes(4) );
			
			int flags = (flagsAndOffset & 0xE000) >> 13;
			int offset = flagsAndOffset & 0x1FFF;
			
			// Options don't appear to be used that much, so we'll skip over them for simplicity.
			// If they're ever needed, then they would be interpreted here.
			if( ihl > 5 )
				in.skipNBytes( (ihl-5) * 4L );
			
			int payloadSize = totalLength - (ihl * 4);
			byte[] payloadBytes = in.readNBytes( payloadSize );
			
			// Notify IPv4 consumer
			Ip4Layer me = new Ip4Layer( parent, 
			                            tos, 
			                            identification, 
			                            flags, 
			                            offset, 
			                            ttl, 
			                            proto,
			                            checksum, 
			                            sourceAddr, 
			                            destAddr, 
			                            payloadBytes );
			
			// Notify IP4 Consumer
			if( ip4Consumer != null )
				ip4Consumer.accept( me );
			
			// IP4 allows fragmentation over multiple frames, which is handled by the IP Fragment 
			// Manager. If the result is an incomplete sequence (e.g. more fragments to come) then
			// we don't have enough data to pass up the stack, so exit here.
			Ip4FragmentManager.SequenceResult result = ipFragmentManager.processFrame( me );
			if( !result.isComplete() )
				return me;
			
			ProtocolLayer inmostLayer = me;
			
			// Find processor for next level
			switch( proto )
			{
				case IpConstants.IPPROTO_UDP:
					inmostLayer = processUdp( me, result.getPayload() );
					break;
				case IpConstants.IPPROTO_TCP:
					inmostLayer = processTcp( me, result.getPayload() );
					break;
				default:
					break;
			}
			
			return inmostLayer;
		}
	}
	
	/**
	 * Interprets binary data as an UDP frame.
	 * <p/>
	 * This method will notify the registered UDP consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param parent the {@link ProtocolLayer} that contains this UDP layer
	 * @param data the UDP data in binary form
	 * @return the in-most layer within this UDP packet that the interpreter could understand
	 * @throws IOException if there was an error reading the UDP data
	 * 
	 * @see onUdp
	 */
	private ProtocolLayer processUdp( ProtocolLayer parent, byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			int sourcePort = in.readUint16();
			int destPort = in.readUint16();
			int length = in.readUint16();
			int checksum = in.readUint16();
			
			int udpPayloadSize = length - 8;
			byte[] udpPayload = in.readNBytes( udpPayloadSize );
			
			// Notify UDP consumer
			UdpLayer me = new UdpLayer( parent, sourcePort, destPort, checksum, udpPayload );
			if( this.udpConsumer != null )
				this.udpConsumer.accept( me );
			
			return me;
		}
	}
	
	/**
	 * Interprets binary data as a TCP frame.
	 * <p/>
	 * This method will notify the registered TCP consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param parent the {@link ProtocolLayer} that contains this TCP layer
	 * @param data the TCP data in binary form
	 * @return the in-most layer within this TCP packet that the interpreter could understand
	 * @throws IOException if there was an error reading the TCP data
	 * 
	 * @see onTcp
	 */
	private ProtocolLayer processTcp( ProtocolLayer parent, byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			int sourcePort = in.readUint16();
			int destPort = in.readUint16();
			long seqNumber = in.readUint32();
			long ackNumber = in.readUint32();
			int dataOffset = in.readUnsignedByte() >> 4;
			int flags = in.readUnsignedByte();
			int window = in.readUint16();
			int checksum = in.readUint16();
			int urgentPointer = in.readUint16();
			
			List<TcpOption> options = new ArrayList<>();
			
			// TCP Options
			if( dataOffset > 5 )
			{
				int optionSectionLength = (dataOffset - 5) * 4;
				byte[] optionData = in.readNBytes( optionSectionLength );
				options.addAll( processTcpOptions(optionData) );
			}
			
			int payloadLen = data.length - (dataOffset * 4);
			byte[] payload = in.readNBytes( payloadLen );
			
			// Notify TCP consumer
			TcpLayer me = new TcpLayer( parent, 
			                            sourcePort, 
			                            destPort, 
			                            seqNumber, 
			                            ackNumber, 
			                            flags, 
			                            window, 
			                            checksum, 
			                            urgentPointer, 
			                            options, 
			                            payload );

			if( this.tcpConsumer != null )
				this.tcpConsumer.accept( me );
			
			return me;
		}
	}
	
	private Collection<TcpOption> processTcpOptions( byte[] data ) throws IOException
	{
		List<TcpOption> options = new ArrayList<>();
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			int optionType = in.readUnsignedByte();
			while( optionType != TcpConstants.TCP_OPT_EOL )
			{
				if( optionType != TcpConstants.TCP_OPT_NOOP )
				{
					// Option Len is length of the whole structure which includes size of type 
					// and length fields as well as the size of the data field
					int optionLen = in.readUnsignedByte();
					int optionDataLen = optionLen - 2;
					byte[] optionData = in.readNBytes( optionDataLen );

					options.add( new TcpOption(optionType, optionData) );
				}
				
				// Can't rely on TCP_OPT_EOL being present it seems :(
				if( in.available() == 0 )
					break;
				
				// Read next option type
				optionType = in.readUnsignedByte();
			}
		}

		return options;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * Registers a function that will be called whenever an {@link EnhancedPacketBlock} is
	 * submitted to the interpreter for processing
	 *  
	 * @param consumer the function to be called when an {@link EnhancedPacketBlock} is
	 *                 submitted
	 * 
	 * @see EnhancedPacketBlock
	 */
	public void onPacket( Consumer<PacketLayer> consumer )
	{
		this.packetConsumer = consumer;
	}
	
	/**
	 * Registers a function that will be called whenever an Ethernet frame is discovered during
	 * packet interpretation.
	 *  
	 * @param consumer the function to be called when an Ethernet frame is discovered
	 * 
	 * @see EthernetLayer
	 */
	public void onEthernet( Consumer<EthernetLayer> consumer )
	{
		this.ethernetConsumer = consumer;
	}
	
	/**
	 * Registers a function that will be called whenever an Raw IP frame is discovered during
	 * packet interpretation.
	 *  
	 * @param consumer the function to be called when an Raw IP frame is discovered
	 * 
	 * @see RawLayer
	 */
	public void onRawFrame( Consumer<RawLayer> consumer )
	{
		this.rawConsumer = consumer;
	}
	
	/**
	 * Registers a function that will be called whenever an IPv4 frame is discovered during
	 * packet interpretation.
	 *  
	 * @param consumer the function to be called when an IPv4 frame is discovered
	 * 
	 * @see Ip4Layer
	 */
	public void onIp4( Consumer<Ip4Layer> consumer )
	{
		this.ip4Consumer = consumer;
	}
	
	/**
	 * Registers a function that will be called whenever an UDP frame is discovered during
	 * packet interpretation.
	 *  
	 * @param consumer the function to be called when an UDP frame is discovered
	 * 
	 * @see UdpLayer
	 */
	public void onUdp( Consumer<UdpLayer> consumer )
	{
		this.udpConsumer = consumer;
	}
	
	/**
	 * Registers a function that will be called whenever an TCP frame is discovered during
	 * packet interpretation.
	 *  
	 * @param consumer the function to be called when a TCP frame is discovered
	 * 
	 * @see TcpLayer
	 */
	public void onTcp( Consumer<TcpLayer> consumer )
	{
		this.tcpConsumer = consumer;
	}
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
