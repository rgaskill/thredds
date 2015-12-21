/*
 * Copyright (c) 1998 - 2012. University Corporation for Atmospheric Research/Unidata
 * Portions of this software were developed by the Unidata Program at the
 * University Corporation for Atmospheric Research.
 *
 * Access and use of this software shall impose the following obligations
 * and understandings on the user. The user is granted the right, without
 * any fee or cost, to use, copy, modify, alter, enhance and distribute
 * this software, and any derivative works thereof, and its supporting
 * documentation for any purpose whatsoever, provided that this entire
 * notice appears in all copies of the software, derivative works and
 * supporting documentation.  Further, UCAR requests that the user credit
 * UCAR/Unidata in any publications that result from the use of this
 * software or in any product that includes this software. The names UCAR
 * and/or Unidata, however, may not be used in any advertising or publicity
 * to endorse or promote any products or commercial entity unless specific
 * written permission is obtained from UCAR/Unidata. The user also
 * understands that UCAR/Unidata is not obligated to provide the user with
 * any support, consulting, training or assistance of any kind with regard
 * to the use, operation and performance of this software nor to provide
 * the user with any updates, revisions, new versions or "bug fixes."
 *
 * THIS SOFTWARE IS PROVIDED BY UCAR/UNIDATA "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL UCAR/UNIDATA BE LIABLE FOR ANY SPECIAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE ACCESS, USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ucar.nc2.util.net;

import org.apache.http.HttpEntity;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import ucar.httpservices.*;
import ucar.nc2.util.net.EchoService;
import ucar.nc2.util.UnitTestCommon;
import ucar.unidata.test.util.NeedsExternalResource;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Test HttpFormBuilder
 */
@Category(NeedsExternalResource.class)
public class TestFormBuilder extends UnitTestCommon
{

    //////////////////////////////////////////////////
    // Constants

    static final boolean DEBUG = false;

    static final int SIMPLEECHOPORT = 4444;
    static final int MULTIECHOPORT = 4445;
    static final String SIMPLEECHOURL = "http://localhost:" + SIMPLEECHOPORT;
    static final String MULTIECHOURL = "http://localhost:" + MULTIECHOPORT;

    // Field values to use
    static final String DESCRIPTIONENTRY = "TestFormBuilder";
    static final String NAMEENTRY = "Mr. Jones";
    static final String EMAILENTRY = "idv@ucar.edu";
    static final String ORGENTRY = "UCAR";
    static final String SUBJECTENTRY = "hello";
    static final String SOFTWAREPACKAGEENTRY = "IDV";
    static final String VERSIONENTRY = "1.0.1";
    static final String HARDWAREENTRY = "x86";
    static final String OSTEXT = System.getProperty("os.name");
    static final String EXTRATEXT = "extra";
    static final String BUNDLETEXT = "bundle";
    static final String ATTACHTEXT = "arbitrary data\n";

    static protected final String FAKEBOUNDARY = "XXXXXXXXXXXXXXXXXXXX";
    static protected final String FAKEATTACH3 = "attach3XXXXXXXXXXXXXXXXXXXX.txt";

    static final char QUOTE = '"';
    static final char COLON = ':';

    //////////////////////////////////////////////////
    // Instance Variables

    int passcount = 0;
    int xfailcount = 0;
    int failcount = 0;
    boolean verbose = true;
    boolean pass = false;

    protected String boundary = null;

    File attach3file = null;

    //////////////////////////////////////////////////
    // Constructor(s)

    public TestFormBuilder()
    {
        setTitle("HTTPFormBuilder test(s)");
        setSystemProperties();
    }

    @Test
    public void
    testSimple()
            throws Exception
    {
        pass = true;
        try {
            HTTPFormBuilder builder = buildForm(false);
            HttpEntity content = builder.build();
            String body = null;
            try (
                    EchoService echo = new EchoService(SIMPLEECHOPORT).startecho();
                    HTTPMethod postMethod = HTTPFactory.Post(SIMPLEECHOURL)
            ) {
                postMethod.setRequestContent(content);
                postMethod.execute();
                int code = postMethod.getStatusCode();
                if(code != 200)
                    throw new IOException("Bad return code: " + code);
                body = postMethod.getResponseAsString();
            }
            if(DEBUG || prop_visual)
                visual("TestFormBuilder.testsimple.RAW", body);
            body = genericize(body, OSTEXT, null, null);
            if(DEBUG)
                visual("TestFormBuilder.testsimple.LOCALIZED", body);
            String diffs = UnitTestCommon.compare("TestFormBuilder.testSimpl", simplebaseline, body);
            if(diffs != null) {
                System.err.println("TestFormBuilder.testsimple.diffs:\n" + diffs);
                Assert.assertTrue("TestFormBuilder.testSimple: ***FAIL", false);
            }
        } catch (Exception e) {
            System.err.println("***FAIL: "+e.getMessage());
            System.err.flush();
            pass = false;
        }
        Assert.assertTrue("TestFormBuilder.simple: failed", pass);
    }

    @Test
    public void
    testMultiPart()
            throws Exception
    {
        // Try to create a tmp file
        attach3file = HTTPUtil.fillTempFile("attach3.txt", ATTACHTEXT);
        attach3file.deleteOnExit();

        pass = true;
        try {
            HTTPFormBuilder builder = buildForm(true);
            HttpEntity content = builder.build();
            String body = null;
            try (
                    EchoService echo = new EchoService(MULTIECHOPORT).startecho();
                    HTTPMethod postMethod = HTTPFactory.Post(MULTIECHOURL)
            ) {
                postMethod.setRequestContent(content);
                postMethod.execute();
                int code = postMethod.getStatusCode();
                if(code != 200)
                    throw new IOException("Bad return code: " + code);
                body = postMethod.getResponseAsString();
            }
            if(DEBUG || prop_visual)
                visual("TestFormBuilder.testmultipart.RAW", body);
            String boundary = getboundary(body);
            Assert.assertTrue("Missing boundary info", boundary != null);
            String attach3 = getattach(body, "attach3");
            Assert.assertTrue("Missing attach3 info", attach3 != null);
            body = genericize(body, OSTEXT, boundary, attach3);
            if(DEBUG)
                visual("TestFormBuilder.testmultipart.LOCALIZED", body);
            String diffs = UnitTestCommon.compare("TestFormBuilder.testMultiPart", multipartbaseline, body);
            if(diffs != null) {
                System.err.println("TestFormBuilder.testmultipart.diffs:\n" + diffs);
                Assert.assertTrue("TestFormBuilder.testmultipart: ***FAIL", false);
            }
        } catch (Exception exc) {
            exc.printStackTrace();
            pass = false;
        }
        Assert.assertTrue("TestFormBuilder.multipart: failed", pass);
    }

    protected HTTPFormBuilder buildForm(boolean multipart)
            throws HTTPException
    {
        HTTPFormBuilder builder = new HTTPFormBuilder();

        /*
        StringBuffer javaInfo = new StringBuffer();
        javaInfo.append("Java: home: " + System.getProperty("java.home"));
        javaInfo.append(" version: " + System.getProperty("java.version"))
        */

        builder.add("fullName", NAMEENTRY);
        builder.add("emailAddress", EMAILENTRY);
        builder.add("organization", ORGENTRY);
        builder.add("subject", SUBJECTENTRY);
        builder.add("description", DESCRIPTIONENTRY);
        builder.add("softwarePackage", SOFTWAREPACKAGEENTRY);
        builder.add("packageVersion", VERSIONENTRY);
        builder.add("os", OSTEXT);
        builder.add("hardware", HARDWAREENTRY);

        if(multipart) {
            // Use bytes
            builder.add("attachmentOne", EXTRATEXT.getBytes(HTTPUtil.ASCII), "extra.html");
            // Use Inputstream
            byte[] bytes = BUNDLETEXT.getBytes(HTTPUtil.UTF8);
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            builder.add("attachmentTwo", bis, "bundle.xidv");
            if(attach3file != null) {
                // Use File
                builder.add("attachmentThree", attach3file);
            }
        }
        return builder;
    }

    protected String getboundary(String text)
            throws HTTPException
    {
        // Ignore all the headers except the content-type for
        // the multipart part.
        String[] lines = text.split("[\n]");
        int pos = -1;
        String boundary = null;
        for(int i = 0; i < lines.length; i++) {
            String line = lines[i];
            line = line.replace("\r", "");
            if(line.length() == 0)
                break;
            Map<String, String> map = parseheaderline(line);
            if(map == null) continue;
            if(map.get("PREFIX").equals("content-type")) {
                boundary = map.get("boundary");
                Assert.assertTrue("Missing boundary", boundary != null);
            }
        }
        return boundary;
    }

    protected String getattach(String text, String attachfile)
            throws HTTPException
    {
        String attach3 = null;
        String[] lines = text.split("[\n]");
        int pos = -1;
        String boundary = null;
        for(int i = 0; i < lines.length; i++) {
            String line = lines[i];
            line = line.replace("\r", "");
            Map<String, String> map = parseheaderline(line);
            if(map == null) continue;
            String prefix = map.get("PREFIX");
            if(prefix.equals("content-disposition")) {
                if(map.get("name").equals("attachmentThree")) {
                    attach3 = map.get("filename");
                    Assert.assertTrue("Missing attach3 filename", attach3 != null);
                }
            }
        }
        return attach3;
    }

    protected String genericize(String text, String os, String boundary, String attach3name)
            throws HTTPException
    {
        text = text.replace("\r", "");
        // Ignore all the headers
        String[] lines = text.split("[\n]");
        int pos = -1;
        for(int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if(line.length() == 0) {
                pos = i;
                break;
            }
        }
        if(pos < 0) return null;
        StringBuilder newtext = new StringBuilder();
        for(int i = pos + 1; i < lines.length; i++) {
            String line = lines[i];
            newtext.append(line);
            newtext.append("\n");
        }
        text = newtext.toString();
        // Generic os: Handle case with and without blank
        text = text.replace(os, "<OSNAME>");
        os = os.replace(' ', '+');
        text = text.replace(os, "<OSNAME>");
        if(boundary != null) {
            // Convert to generic 
            text = text.replace(boundary, FAKEBOUNDARY);
        }
        if(attach3name != null) {
            // Convert to generic 
            text = text.replace(attach3name, FAKEATTACH3);
        }
        return text;
    }

    protected Map<String, String>
    parseheaderline(String line)
    {
        Map<String, String> map = new HashMap<>();
        map.put("PREFIX",""); // default
        if(line == null || line.length() == 0)
            return map;
        int i = line.indexOf(":");
        if(i < 0) {
            map.put("PREFIX", line);
            return map;
        }
        map.put("PREFIX", line.substring(0, i).trim().toLowerCase());
        line = line.substring(i + 1).trim();
        String[] pieces = line.split("[ \t]*[;][ \t]*");
        if(pieces.length == 1) {
            map.put(pieces[0], "");
            return map;
        }
        for(String piece : pieces) {
            String[] pair = piece.split("[=]");
            String value = "";
            String key = pair[0];
            switch (pair.length) {
            case 1:
                break;
            case 2:
            default:
                value = pair[1].trim();
                if(value.charAt(0) == '"')
                    value = value.substring(1, value.length() - 1);
                break;
            }
            map.put(key, value);
        }
        return map;
    }

    static final String patb = "--.*";
    static final Pattern blockb = Pattern.compile(patb);

    static final String patcd =
            "Content-Disposition:\\s+form-data;\\s+name=[\"]([^\"]*)[\"]";
    static final Pattern blockcd = Pattern.compile(patcd);
    static final String patcdx = patcd
            + "\\s*[;]\\s+filename=[\"]([^\"]*)[\"]";
    static final Pattern blockcdx = Pattern.compile(patcdx);

    protected Map<String, String> parsemultipartbody(String body)
            throws IOException
    {
        Map<String, String> map = new TreeMap<>();
        body = body.replace("\r\n", "\n");
        StringReader sr = new StringReader(body);
        BufferedReader rdr = new BufferedReader(sr);
        String line = rdr.readLine();
        if(line == null)
            throw new HTTPException("Empty body");
        for(; ; ) { // invariant is that the next unconsumed line is in line
            String name = null;
            String filename = null;
            StringBuilder value = new StringBuilder();
            if(!line.startsWith("--"))
                throw new HTTPException("Missing boundary marker : " + line);
            line = rdr.readLine();
            // This might have been the trailing boundary marker
            if(line == null)
                break;
            if(line.toLowerCase().startsWith("content-disposition")) {
                // Parse the content-disposition
                Matcher mcd = blockcdx.matcher(line); // try extended
                if(!mcd.lookingAt()) {
                    mcd = blockcd.matcher(line);
                    if(!mcd.lookingAt())
                        throw new HTTPException("Malformed Content-Disposition marker : " + line);
                    name = mcd.group(1);
                } else {
                    name = mcd.group(1);
                    filename = mcd.group(2);
                }
            } else
                throw new HTTPException("Missing Content-Disposition marker : " + line);
            // Treat content-type line as optional; may or may not have charset
            line = rdr.readLine();
            if(line.toLowerCase().startsWith("content-type")) {
                line = rdr.readLine();
            }
            // treat content-transfer-encoding line as optional
            if(line.toLowerCase().startsWith("content-transfer-encoding")) {
                line = rdr.readLine();
            }
            // Skip one blank line
            line = rdr.readLine();
            // Extract the content
            value.setLength(0);
            while(!line.startsWith("--")) {
                value.append(line);
                value.append("\n");
                line = rdr.readLine();
            }
            map.put(name, value.toString());
        }
        return map;
    }

    static protected String join(String[] pieces, int offset, String sep)
    {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for(int i = offset; i < pieces.length; i++) {
            if(first) buf.append(sep);
            first = false;
            buf.append(pieces[i]);
        }
        return buf.toString();
    }

    static protected String mapjoin(Map<String, String> map, String sep1, String sep2)
    {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for(Map.Entry<String, String> entry : map.entrySet()) {
            if(!first) buf.append(sep1);
            first = false;
            buf.append(entry.getKey());
            buf.append(sep2);
            buf.append(entry.getValue());
        }
        return buf.toString();
    }

    static final String simplebaseline =
            "softwarePackage=IDV&emailAddress=idv%40ucar.edu&os=<OSNAME>&subject=hello&organization=UCAR&fullName=Mr.+Jones&description=TestFormBuilder&packageVersion=1.0.1&hardware=x86";

    static final String multipartbaseline =
            "--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"softwarePackage\"\n\nIDV\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"emailAddress\"\n\nidv@ucar.edu\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"os\"\n\n<OSNAME>\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"subject\"\n\nhello\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"attachmentTwo\"; filename=\"bundle.xidv\"\nContent-Type: application/octet-stream\n\nbundle\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"organization\"\n\nUCAR\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"fullName\"\n\nMr. Jones\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"description\"\n\nTestFormBuilder\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"attachmentThree\"; filename=\"attach3XXXXXXXXXXXXXXXXXXXX.txt\"\nContent-Type: application/octet-stream; charset=US-ASCII\n\narbitrary data\n\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"packageVersion\"\n\n1.0.1\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"attachmentOne\"; filename=\"extra.html\"\nContent-Type: application/octet-stream\n\nextra\n--XXXXXXXXXXXXXXXXXXXX\nContent-Disposition: form-data; name=\"hardware\"\n\nx86\n--XXXXXXXXXXXXXXXXXXXX--\n";

}
