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
package org.openlvc.sombrero;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Static class containing PCAP constant definitions
 */
public class PcapConstants
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	public static final long TCPDUMP_HEADER_MAGIC_MICROS = 0xA1B2C3D4L;
	public static final long TCPDUMP_HEADER_MAGIC_NANOS  = 0xA1B23C4DL;
	
	//
	// Block Types
	//
	public static final long BLOCKTYPE_SHB = 0x0A0D0D0AL;
	public static final long BLOCKTYPE_IDB = 0x00000001L;
	public static final long BLOCKTYPE_ISB = 0x00000005L;
	public static final long BLOCKTYPE_EPB = 0x00000006L;
	
	//
	// Ethernet Types (not complete)
	// See https://en.wikipedia.org/wiki/EtherType for complete list
	//
	public static final int ETHERTYPE_IP4 = 0x0800;
	public static final int ETHERTYPE_IP6 = 0x86DD;
	
	//
	// Link Types (not complete)
	// See `PCAP and PCAPNG LINKTYPE Registry` for complete list 
	//
	public static final int LINKTYPE_NULL      = 0;
	public static final int LINKTYPE_ETHERNET  = 1;
	public static final int LINKTYPE_RAW       = 101;
	
	//
	// Option Types
	//
	// Shared
	public static final int OPT_ENDOFOPT = 0;
	public static final int OPT_COMMENT  = 1;
	
	// Section Header Block Options
	public static final int OPT_SHB_HARDWARE = 2;
	public static final int OPT_SHB_OS       = 3;
	public static final int OPT_SHB_USERAPPL = 4;
	
	// Interface Description Block Options
	public static final int OPT_IF_NAME        = 2;
	public static final int OPT_IF_DESCRIPTION = 3;
	public static final int OPT_IF_IPV4ADDR    = 4;
	public static final int OPT_IF_IPV6ADDR    = 5;
	public static final int OPT_IF_MACADDR     = 6;
	public static final int OPT_IF_EUIADDR     = 7;
	public static final int OPT_IF_SPEED       = 8;
	public static final int OPT_IF_TSRESOL     = 9;
	public static final int OPT_IF_TZONE       = 10;
	public static final int OPT_IF_FILTER      = 11;
	public static final int OPT_IF_OS          = 12;
	public static final int OPT_IF_FCSLEN      = 13;
	public static final int OPT_IF_TSOFFSET    = 14;
	public static final int OPT_IF_HARDWARE    = 15;
	public static final int OPT_IF_TXSPEED     = 16;
	public static final int OPT_IF_RXSPEED     = 17;
	public static final int OPT_IF_IANATZNAME  = 18;
	
	// Interface Statistics Block Options
	public static final int OPT_ISB_STARTTIME    = 2;
	public static final int OPT_ISB_ENDTIME      = 3;
	public static final int OPT_ISB_IFRECV       = 4;
	public static final int OPT_ISB_IFDROP       = 5;
	public static final int OPT_ISB_FILTERACCEPT = 6;
	public static final int OPT_ISB_OSDROP       = 7;
	public static final int OPT_ISB_USRDELIV     = 8;
	
	//
	// IP Protocol Types (incomplete)
	// See https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers for complete list
	//
	public static final int IPPROTO_TCP = 6;
	public static final int IPPROTO_UDP = 17;
	
	//
	// SnapLen special values
	//
	public static final int SNAPLEN_UNLIMITED = 0;
	
	//
	// Misc Types
	//
	public static final Instant DEFAULT_TIMSTAMPOFFSET         = Instant.EPOCH;
	public static final ChronoUnit DEFAULT_TIMESTAMPRESOLUTION = ChronoUnit.MICROS;
	
	
	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	private PcapConstants() {}

	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
	/**
	 * @return the binary palindrome that represents a PcapNG Section Header Block
	 */
	public static final byte[] getPcapNgShbPalindrome()
	{
		return new byte[] { 0x0A, 0x0D, 0x0D, 0x0A };
	}
}
