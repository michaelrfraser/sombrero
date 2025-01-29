/*
 *   Copyright 2025 Calytrix Technologies
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

/**
 * Static class containing Internet Protocol constant values
 * 
 * @see Ip4Layer
 */
public class IpConstants
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	//
	// IP Protocol Types (incomplete)
	// See https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers for complete list
	//
	/** Internet Control Message Protocol (1) */
	public static final int IPPROTO_ICMP = 0x01;
	/** Internet Group Management Protocol (2) */
	public static final int IPPROTO_IGMP = 0x02;
	/** Transmission Control Protocol (6)*/
	public static final int IPPROTO_TCP = 0x06;
	/** User Datagram Protocol (17) */
	public static final int IPPROTO_UDP = 0x11;

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	private IpConstants() {};

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
	 * Returns the human readable name of an IPPROTO value (e.g. IPPROTO_TCP)
	 * <p/>
	 * If the IPPROTO value is not known, <code>null</code> will be returned.
	 * 
	 * @param ipProto the IPPROTO value to return the name for
	 * @param brief <code>true</code> if the method should return an abbreviation, otherwise
	 *              <code>false</code> for the full protocol name
	 * @return a textual representation of the specified IPPROTO value, or 
	 *         <code>null</code> if the IPPROTO value is not known
	 */
	public static String getIpProtoName( int ipProto, boolean brief )
	{
		switch( ipProto )
		{
			case IPPROTO_ICMP: return brief ? "ICMP" : "Internet Control Message Protocol";
			case IPPROTO_IGMP: return brief ? "IGMP" : "Internet Group Management Protocol";
			case IPPROTO_TCP:  return brief ? "TCP"  : "Transmission Control Protocol";
			case IPPROTO_UDP:  return brief ? "UDP"  : "User Datagram Protocol";
			default:
				return null;
		}
	}
}
