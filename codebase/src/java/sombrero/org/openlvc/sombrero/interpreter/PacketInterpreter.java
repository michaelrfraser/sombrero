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
import java.util.Arrays;
import java.util.function.Consumer;

import org.openlvc.sombrero.PcapConstants;
import org.openlvc.sombrero.block.EnhancedPacketBlock;
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
	private Consumer<EthernetLayer>       ethernetConsumer;
	private Consumer<RawLayer>            rawConsumer;
	private Consumer<Ip4Layer>            ip4Consumer;
	private Consumer<UdpLayer>            udpConsumer;

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------
	/**
	 * Processes the contents of an {@link EnhancedPacketBlock}, notifying registered consumers
	 * as corresponding protocol layers are found.
	 * 
	 * @param packet the packet to process
	 * @throws IOException if there was an error reading the contents of the packet
	 * @throws IllegalArgumentException if the packet was captured from an unsupported link type
	 */
	public void process( EnhancedPacketBlock packet ) throws IOException
	{
		byte[] packetData = packet.getPacketData();
		
		// Ignore truncated packets
		if( packet.isTruncated() )
			return;
		
		switch( packet.getInterface().getLinkType() )
		{
			case PcapConstants.LINKTYPE_NULL, PcapConstants.LINKTYPE_ETHERNET:
				processEthernet( packetData );
				break;
			
			case PcapConstants.LINKTYPE_RAW:
				processRaw( packetData );
				break;
			
			// Still unsure whether this should either be ignored, or reported back through an
			// unknown link layer consumer. Leaving as exception for now so the behavior is
			// explicit
			default:
				throw new IllegalArgumentException( "unsupported link type "+packet.getInterface().getLinkType() );
		}
	}

	/**
	 * Interprets binary data as a raw ethernet frame.
	 * <p/>
	 * This method will notify the registered ethernet consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param data the ethernet data in binary form
	 * @throws IOException if there was an error reading the ethernet data
	 * 
	 * @see #onEthernet(Consumer)
	 */
	private void processEthernet( byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			byte[] destination = in.readNBytes( 6 ); // Destination MAC Address
			byte[] source = in.readNBytes( 6 );      // Source MAC Address
			int type = in.readUint16();
			byte[] payloadBytes = Arrays.copyOfRange( data, 14, data.length );

			// Notify ethernet consumer
			EthernetLayer me = new EthernetLayer( destination, source, type, payloadBytes );
			if( ethernetConsumer != null )
				ethernetConsumer.accept( me );

			// Find processor for next level 
			if( type == PcapConstants.ETHERTYPE_IP4 )
				processIPv4( me, payloadBytes );
		}
	}
	
	/**
	 * Interprets binary data as a raw IP frame.
	 * <p/>
	 * This method will notify the registered raw consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param data the raw IP data in binary form
	 * @throws IOException if there was an error reading the raw IP data
	 * 
	 * @see #onRawFrame(Consumer)
	 */
	private void processRaw( byte[] data ) throws IOException
	{
		if( data.length < 4 )
			return;
		
		// Notify raw frame consumer
		RawLayer me = new RawLayer( data );
		if( rawConsumer != null )
			rawConsumer.accept( me );
		
		// Find processor for next level by peeking version byte to determine route
		int version = data[0] >> 4;
		if( version == 4 )
			processIPv4( me, data );
	}
	
	/**
	 * Interprets binary data as an IPv4 frame.
	 * <p/>
	 * This method will notify the registered IPv4 consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param data the IPv4 data in binary form
	 * @throws IOException if there was an error reading the IPv4 data
	 * 
	 * @see #onIp4(Consumer)
	 */
	public void processIPv4( ProtocolLayer parent, byte[] data ) throws IOException
	{
		try( PcapInputStream in = PcapInputStream.create(data, Endianness.Big) )
		{
			int firstOct = in.readUint8();
			int ihl = firstOct & 0x0F;
			
			int tos = in.readUint8();
			int totalLength = in.readUint16();
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
			
			if( ip4Consumer != null )
				ip4Consumer.accept( me );
			
			// Find processor for next level 
			if( proto == PcapConstants.IPPROTO_UDP )
				processUdp( me, payloadBytes );
		}
	}
	
	/**
	 * Interprets binary data as an UDP frame.
	 * <p/>
	 * This method will notify the registered UDP consumer of the frame, and will attempt
	 * to find a child-processor method for the data contained within
	 * 
	 * @param data the UDP data in binary form
	 * @throws IOException if there was an error reading the UDP data
	 * 
	 * @see onUdp
	 */
	public void processUdp( ProtocolLayer parent, byte[] data ) throws IOException
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
		}
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////
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
	
	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
