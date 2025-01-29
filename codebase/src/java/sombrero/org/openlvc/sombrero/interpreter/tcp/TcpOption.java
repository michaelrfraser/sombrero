/*
 *   Copyright 2025 Open LVC Project.
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

import java.util.Collection;
import java.util.Optional;

public record TcpOption( int type, byte[] data )
{
	public static Optional<TcpOption> getOption( Collection<TcpOption> options, int type )
	{
		return options.stream().filter( o -> o.type() == type ).findFirst();
	}
}
