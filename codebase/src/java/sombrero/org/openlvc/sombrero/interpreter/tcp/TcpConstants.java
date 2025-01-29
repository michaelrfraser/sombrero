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
package org.openlvc.sombrero.interpreter.tcp;

/**
 * Static class containing TCP constant values
 * 
 * @see TcpLayer
 */
public class TcpConstants
{
	//----------------------------------------------------------
	//                    STATIC VARIABLES
	//----------------------------------------------------------
	//
	// TCP Flags
	//
	/** Congestion Window Reduced */
	public static final int TCP_FLAG_CWR_MASK = 0x80;
	/** ECN-Echo */
	public static final int TCP_FLAG_ECE_MASK = 0x40;
	/** Urgent pointer field is significant **/
	public static final int TCP_FLAG_URG_MASK = 0x20;
	/** Acknowledgement field is significant **/
	public static final int TCP_FLAG_ACK_MASK = 0x10;
	/** Push buffered data to receiving application */
	public static final int TCP_FLAG_PSH_MASK = 0x08;
	/** Reset the connection */
	public static final int TCP_FLAG_RST_MASK = 0x04;
	/** Synchronize sequence numbers */
	public static final int TCP_FLAG_SYN_MASK = 0x02;
	/** Last packet from sender */
	public static final int TCP_FLAG_FIN_MASK = 0x01;
	
	//
	// TCP Options
	//
	/** End of options list */
	public static final int TCP_OPT_EOL = 0;
	/** Noop (used for padding */
	public static final int TCP_OPT_NOOP = 1;
	/** Maximum segment size */
	public static final int TCP_OPT_MSS = 2;
	/** Window scale */
	public static final int TCP_OPT_WINDOW_SCALE = 3;
	/** Selective Acknowledgement permitted */
	public static final int TCP_OPT_SACK_PERMITTED = 4;
	/** Selective Acknowledgement */
	public static final int TCP_OPT_SACK = 5;
	/** Timestamp and echo */
	public static final int TCP_OPT_TIMESTAMP_AND_ECHO = 8;
	/** User Timeout */
	public static final int TCP_OPT_USER_TIMEOUT = 28;
	/** TCP Authentication */
	public static final int TCP_OPT_AUTHENTICATION = 29;
	/** Multipath TCP */
	public static final int TCP_OPT_MTCP = 30;

	//----------------------------------------------------------
	//                   INSTANCE VARIABLES
	//----------------------------------------------------------

	//----------------------------------------------------------
	//                      CONSTRUCTORS
	//----------------------------------------------------------
	private TcpConstants() {};
	
	//----------------------------------------------------------
	//                    INSTANCE METHODS
	//----------------------------------------------------------

	////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////// Accessor and Mutator Methods ///////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////

	//----------------------------------------------------------
	//                     STATIC METHODS
	//----------------------------------------------------------
}
