Sombrero: pure-java library for reading PcapNG and tcpdump network captures
===================
-------------------

Welcome to OpenLVC's Sombrero project!

Sombrero is a library for working with and wrangling network captures stored in PcapNG and Tcpdump formats

The project began due to a lack of pure-java options that can handle both formats of pcap files, and
also provide a means to interpret their contents

Using Sombrero to read PcapNG/Tcpdump files
----------
Sombrero's `IPcapReader` is your one stop shop for reading both PcapNG and Tcpdump files!

To create a reader instance use the factory method `IPcapReader#createFor(InputStream)` e.g.

```
import java.io.File;
import java.io.FileInputStream;

import org.openlvc.sombrero.block.EnhancedPacketBlock;
import org.openlvc.sombrero.block.IPcapBlock;
import org.openlvc.sombrero.reader.IPcapReader;

public class SombreroExample
{
    public static void main( String[] args )
    {
        // The file to read should be in the first argument
        if( args.length == 0 )
            throw new IllegalArgumentException( "Expecting file argument" );
    
        File file = new File( args[0] );
        try( FileInputStream in = new FileInputStream(file) )
        {
            // Create an IPcapReader to read the file
            IPcapReader reader = IPcapReader.createFor( in );
      
            // Read the file's blocks
            IPcapBlock block = reader.nextBlock();
            while( block != null )
            {
                // For this example, we only care about packet information in the file
                if( block instanceof EnhancedPacketBlock packet )
                {
                    String message = String.format( "Packet of %d bytes received at %s", 
                                                    packet.getPacketData().length,
                                                    packet.getTimestamp() );
                    System.out.println( message );
                }
                
                block = reader.nextBlock();
            }
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
    }
}
```

Once you've got an reader instance, call `IPcapReader#nextBlock()` to read in the next information block from the
capture file. The method will return `null` once the end of the file is reached.

The `IPapReader#nextBlock()` method can return any of the following types of block, which you can chose to process
or ignore depending on your application

- `SectionHeaderBlock`: Top-most container of a PcapNG file, contains metadata about the machine that the capture
  file was generated on. A recording will generally have just one of these, although the specification does allow
  for a file to contain multiple
- `InterfaceDescriptionBlock`: Descibes a network interface that data was captured on. A section will have one
  or more of these blocks
- `EnhancedPacketBlock`: Describes a captured packet, including its data and the time it was captured. Most
  applications will only need to concern themselves with processing this type of block.
- `InterfaceStatisticsBlock`: A summary of capture statistics for a particular interface. This is usually found
  at the end of a section.

Interpreting Packet Data with Sombrero
----------
Sombrero provides a `PacketInterpreter` class which dissects the contents of packets and notifies
protocol layer handlers accordingly.

For example, if we are interested in UDP packets, we could use the `PacketInterpreter` as such:

```
import java.io.File;
import java.io.FileInputStream;

import org.openlvc.sombrero.block.EnhancedPacketBlock;
import org.openlvc.sombrero.block.IPcapBlock;
import org.openlvc.sombrero.interpreter.PacketInterpreter;
import org.openlvc.sombrero.reader.IPcapReader;

public class SombreroExample
{
    public static void main( String[] args )
    {
        // The file to read should be in the first argument
        if( args.length == 0 )
            throw new IllegalArgumentException( "Expecting file argument" );
    
        // Create a PacketInterpreter to process the packets and register a
        // handler for UDP packets that displays the source and destination port
        // as well as the UDP payload size
        PacketInterpreter interpreter = new PacketInterpreter();
        interpreter.onUdp( udp -> {
            String message = String.format( "UDP packet source=%d, dest=%d, len=%d", 
                                            udp.getSourcePort(),
                                            udp.getDestPort(),
                                            udp.getData().length );
            System.out.println( message );
        });
    
        // Read through the pcap file and pass any packet we come across to
        // the interpreter
        File file = new File( args[0] );
        try( FileInputStream in = new FileInputStream(file) )
        {
            IPcapReader reader = IPcapReader.createFor( in );
            IPcapBlock block = reader.nextBlock();
            while( block != null )
            {
                // Hand off packets to the interpreter, if they're UDP then
                // the function registered above will be called
                if( block instanceof EnhancedPacketBlock packet )
                    interpreter.process( packet );
        
                block = reader.nextBlock();
            }
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
    }
}
```

You can intercept multiple protocol levels by registering handlers for each of them. The layer
information provided to the lambda handler includes the full stack of parsed protocol layers,
so if you wanted the sender and receiver IP Addresses in the above example you could do the following:

```
PacketInterpreter interpreter = new PacketInterpreter();
interpreter.onUdp( udp -> {
    Ip4Layer ip = udp.findParent( Ip4Layer.class );

    String message = String.format( "UDP packet source=%s:%d, dest=%s:%d, len=%d", 
                                    ip.getSourceAddress(),
                                    udp.getSourcePort(),
                                    ip.getDestAddress(),
                                    udp.getDestPort(),
                                    udp.getData().length );
    System.out.println( message );
});
```

**Note:** Currently only a small subset of protocol layers are supported, we'll add to this as time and
demand permits.

Compiling
----------
Compiling Sombrero is extremely simple. You are expected to have a valid JDK on your computer and
accessible from the system path.

Sombrero ships with an embedded copy of Ant and shell scripts to run everything. The major targets are:

```
 $ cd codebase
 $ ./ant sandbox        << generates an "exploded" install in dist/sombrero-x.x.x
 $ ./ant release        << clean, test and general zip file release in dist
 $ ./ant clean          << burninate the peasants
 $ ./ant -projecthelp   << get some more deets
```

The typical way we use it is to run `./ant sandbox` and then cd into `dist/sombrero-x.x.x` where there is now
effectively a Sombrero distribution.

If you run `./ant -projecthelp` you'll get the following:

```
Buildfile: D:\Developer\workspace\opensource\sombrero\codebase\build.xml
     [echo] Build Version: sombrero-1.0.0 (build 0)
 [platform] Operating System platform is: win64
 
                                       888
                                       888
                                       888
       .d8888b   .d88b.  88888b.d88b.  88888b.  888d888 .d88b.  888d888 .d88b.
       88K      d88""88b 888 "888 "88b 888 "88b 888P"  d8P  Y8b 888P"  d88""88b
       "Y8888b. 888  888 888  888  888 888  888 888    88888888 888    888  888
            X88 Y88..88P 888  888  888 888 d88P 888    Y8b.     888    Y88..88P
        88888P'  "Y88P"  888  888  888 88888P"  888     "Y8888  888     "Y88P"

        Open LVC Sombrero is a high-performance, pure-Java library for working
        with network captures stored in PCAPNG and TcpDump formats


Main targets:

 build.release  Set the release build flag for this run
 clean          Removes all generated build artefacts
 compile        Compile all the production code
 installer      Create an installer package from the sandbox
 java.compile   Compile the main projection and test modules
 release        Clean, run all test sand generate a standard release package
 release.thin   Generate a standard release package, but skip the tests
 sandbox        Create a sandbox environment to test and validate in
 test           Compile and run the automated test suite
Default target: sandbox
```

Getting Help
-------------
We're here to help!

Really. We are. We try to answer all queries in between the day job, so some patience is appreciated (as are pull requests!) but please ask away. Just open an Issue on the GitHub repo and we'll respond.


License
--------
Sombrero is released under the Apache Software License v2.
