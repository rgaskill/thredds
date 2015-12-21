/*
 * Copyright 1998-2009 University Corporation for Atmospheric Research/Unidata
 *
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

package ucar.httpservices;


import org.apache.http.HttpHost;
import org.apache.http.client.config.AuthSchemes;

import java.net.URI;
import java.net.URISyntaxException;


/**
 * Provide Auth related utilities
 */

@org.apache.http.annotation.Immutable
abstract public class HTTPAuthUtil
{

    //////////////////////////////////////////////////
    // Constants

    static public final String DEFAULTSCHEME = AuthSchemes.BASIC;

    //////////////////////////////////////////////////
    // HttpHost Utilities

    /**
     * Given a session url httphost and a Method url httphost,
     * Indicate it the are "compatible" as defined as follows.
     * The method httphost is <i>compatible</i> with the session httphost
     * if its host+port is the same as the session's host+port and its scheme is
     * compatible, where e.g. http is compatible with https
     *
     * @param ss Session httphost
     * @param ms Method httphost
     * @return
     */
    static public boolean
    httphostCompatible(HttpHost ss, HttpHost ms)
    {
        assert (ss.getSchemeName() != null && ms.getSchemeName() != null);
        if(!ss.getHostName().equalsIgnoreCase(ms.getHostName()))
            return false;
        if(ss.getPort() != ms.getPort())
            return false;
        String sss = ss.getSchemeName().toLowerCase();
        String mss = ms.getSchemeName().toLowerCase();
        if(!sss.equals(mss)) {
            // Do some special casing
            if(sss.endsWith("s")) sss = sss.substring(0, sss.length() - 1);
            if(mss.endsWith("s")) mss = mss.substring(0, mss.length() - 1);
            if(!sss.equals(mss))
                return false;
        }
        return true;
    }

    /**
     * Given a session url httphost and a Method url httphost,
     * return a new HttpHost that is the upgrade/merge of theother two.
     * Here, upgrade changes the scheme (only) to move http -> https.
     * Assumes httphostCompatible() is true.
     *
     * @param ss Session httphost
     * @param ms Method httphost
     * @return upgraded HttpHost.
     */
    static public HttpHost
    httphostUpgrade(HttpHost ss, HttpHost ms)
    {
        assert (httphostCompatible(ss, ms));
        String sss = ss.getSchemeName().toLowerCase();
        String mss = ms.getSchemeName().toLowerCase();
        String upgrade = sss;
        if(sss.startsWith("http") && mss.startsWith("http")) {
            if(sss.equals("https") || mss.equals("https"))
                upgrade = "https";
        }
        HttpHost host = new HttpHost(ss.getHostName(), ss.getPort(), upgrade);
        return host;
    }

    static public HttpHost
    uriToHttpHost(String surl)
            throws HTTPException
    {
        try {
            URI uri = HTTPUtil.parseToURI(surl);
            return uriToHttpHost(uri);
        } catch (URISyntaxException e) {
            throw new HTTPException(e);
        }
    }

    /**
     * Create an HttpHost from a URI; pull out any principal
     *
     * @param uri to convert
     * @returns an HttpHost instance
     */

    static public HttpHost
    uriToHttpHost(URI uri)
    {
        assert (uri != null);
        return new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());
    }

    static public URI
    httphostToURI(HttpHost httphost)
            throws HTTPException
    {
        try {
            URI url = new URI(httphost.getSchemeName(),
                    null,
                    httphost.getHostName(),
                    httphost.getPort(),
                    "", null, null);
            return url;
        } catch (URISyntaxException mue) {
            throw new HTTPException(mue);
        }
    }

}
