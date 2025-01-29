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
package org.openlvc.sombrero.interpreter.ethernet;

/**
 * Static class containing Ethernet protocol constant values
 * 
 * @see EthernetLayer
 */
public class EthernetConstants
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	//
	// Ethernet Types (not complete)
	// See https://en.wikipedia.org/wiki/EtherType for complete list
	//
	/** Internet Protocol Version 4 */
	public static final int ETHERTYPE_IP4 = 0x0800;
	/** Address Resolution Protocol */
	public static final int ETHERTYPE_ARP = 0x0806;
	/** Internet Protocol Version 6 */
	public static final int ETHERTYPE_IP6 = 0x86DD;
	
	
	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	private EthernetConstants() {};
	
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
	 * Returns the human readable name of an ETHERTYPE value (e.g. ETHERTYPE_IP4)
	 * <p/>
	 * If the ETHERTYPE value is not known, <code>null</code> will be returned.
	 * 
	 * @param etherType the ETHERTYPE value to return the name for
	 * @param brief <code>true</code> if the method should return an abbreviation, otherwise
	 *              <code>false</code> for the full type name
	 * @return a textual representation of the specified ETHERTYPE value, or 
	 *         <code>null</code> if the ETHERTYPE value is not known
	 */
	public static String getEtherTypeName( int etherType, boolean brief )
	{
		switch( etherType )
		{
			case ETHERTYPE_IP4: return brief ? "IPv4" : "Internet Protocol v4";
			case ETHERTYPE_ARP: return brief ? "ARP" : "Address Resolution Protocol";
			case ETHERTYPE_IP6: return brief ? "IPv6"  : "Internet Protocol v6";
			default:
				return null;
		}
	}

	/**
	 * Interprets the provided byte array as an Ethernet MAC address and formats
	 * it in the standard notation (e.g. 01:23:45:67:89:ab)
	 * 
	 * @param hwAddr a byte array representing the MAC address to format
	 * @return a String representing the MAC address in colon separated byte notation
	 */
	public static String formatMacAddress( byte[] hwAddr )
	{
		String[] byteStrings = new String[hwAddr.length];
		for( int i = 0 ; i < hwAddr.length ; ++i )
			byteStrings[i] = String.format( "%02x", hwAddr[i] );
		
		return String.join( ":", byteStrings );
	}
}
