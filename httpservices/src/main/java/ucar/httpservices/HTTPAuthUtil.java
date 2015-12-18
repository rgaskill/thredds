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
import org.apache.http.auth.AuthScope;

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

    // imports from AuthScope
    public static final String ANY_HOST = AuthScope.ANY_HOST;
    public static final int ANY_PORT = AuthScope.ANY_PORT;
    public static final String ANY_REALM = AuthScope.ANY_REALM;
    public static final String ANY_SCHEME = AuthScope.ANY_SCHEME;

    public static final AuthScope ANY = AuthScope.ANY;

    //////////////////////////////////////////////////
    // Scope Utilities

    /**
     * Given a session url scope and a Method url scope,
     * Indicate it the are "compatible" as defined as follows.
     * The method scope is <i>compatible</i> with the session scope
     * if its host+port is the same as the session's host+port and its scheme is
     * compatible, where e.g. http is compatible with https
     *
     * @param ss Session scope
     * @param ms Method scope
     * @return
     */
    static public boolean
    scopeCompatible(AuthScope ss, AuthScope ms)
    {
        if(!ss.getHost().equalsIgnoreCase(ms.getHost()))
            return false;
        if(ss.getPort() != ms.getPort())
            return false;
        String sss = ss.getScheme().toLowerCase();
        String mss = ms.getScheme().toLowerCase();
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
     * Given a session url scope and a Method url scope,
     * "merge" them to produce an HttpHost object where (currently)
     * only the scheme changes to move http -> https.
     * Assumes scopeCompatible() is true.
     *
     * @param ss Session scope
     * @param ms Method scope
     * @return
     */
    static public HttpHost
    scopeToHost(AuthScope ss, AuthScope ms)
    {
        String sss = ss.getScheme();
        String mss = ms.getScheme();
        if(sss != null) sss = sss.toLowerCase();
        if(mss != null) mss = mss.toLowerCase();
        if(sss != null && mss != null) {
            if(sss.equals("https") || mss.equals("https"))
                sss = "https";
        }
        HttpHost host = new HttpHost(ss.getHost(), ss.getPort(), sss);
        return host;
    }

    static public AuthScope
    uriToScope(String surl, String authscheme)
            throws HTTPException
    {
        try {
            URI uri = HTTPUtil.parseToURI(surl);
            return uriToScope(uri, authscheme);
        } catch (URISyntaxException e) {
            throw new HTTPException(e);
        }
    }

    /**
     * Create an AuthScope from a URI; pull out any principal
     *
     * @param uri        to convert
     * @param authscheme
     * @returns an AuthScope instance
     */

    static public AuthScope
    uriToScope(URI uri, String authscheme)
            throws HTTPException
    {
        if(uri == null)
            throw new HTTPException("Null argument");
        try {
            AuthScope scope = new AuthScope(uri.getHost(),
                    uri.getPort(),
                    HTTPAuthUtil.makerealm(uri),
                    authscheme);
            return scope;
        } catch (IllegalArgumentException e) {
            throw new HTTPException(e);
        }
    }

    static public URI
    scopeToURI(AuthScope scope)
            throws HTTPException
    {
        try {
            String scheme = scope.getScheme();
            if(scheme == ANY_SCHEME)
                scheme = "http";
            else if(scheme.equals(HTTPAuthSchemes.SSL))
                scheme = "https";
            else
                scheme = "http";
            URI url = new URI(scheme, null, scope.getHost(), scope.getPort(), "", null, null);
            return url;
        } catch (URISyntaxException mue) {
            throw new HTTPException(mue);
        }
    }

    //////////////////////////////////////////////////
    // Equals and Equivalence interface

    /**
     * Equivalence algorithm:
     * if any field is ANY_XXX, then they are equivalent.
     * Scheme, port, host must all be identical else return false
     * Except: for scheme http == https
     * If this.path is prefix of other.path
     * or other.path is prefix of this.path
     * or they are string equals, then return true
     * else return false.
     */
    /*
    static public boolean equivalent(AuthScope a1, AuthScope a2)
    {
        if(a1 == null || a2 == null)
            throw new NullPointerException();
        if(a1.getScheme() != ANY_SCHEME && a2.getScheme() != ANY_SCHEME
                && !a1.getScheme().equals(a2.getScheme()))
            return false;
        if(a1.getHost() != ANY_HOST && a2.getHost() != ANY_HOST
                && !a1.getHost().equals(a2.getHost()))
            return false;
        if(a1.getPort() != ANY_PORT && a2.getPort() != ANY_PORT
                && a1.getPort() != a2.getPort())
            return false;
        if(a1.getRealm() != ANY_REALM && a2.getRealm() != ANY_REALM
                && !a1.getRealm().equals(a2.getRealm()))
            return false;
        return true;
    }
    */

    /*
    public static boolean equals(AuthScope a1, AuthScope a2)
    {
        if(a2 == null ^ a1 == null)
            return false;
        if(a1 == a2)
            return true;
        // So it turns out that AuthScope#equals does not
        // test port values correctly, so we need to fix here.
        if(true) {
            boolean b1 = HTTPUtil.equals(a1.getHost(), a2.getHost());
            if(!b1 && (a1.getHost() == AuthScope.ANY_HOST || a1.getHost() == AuthScope.ANY_HOST))
                b1 = true;
            int aport = a2.getPort();
            boolean b2 = (a1.getPort() == aport || a1.getPort() == ANY_PORT || aport == ANY_PORT);
            // Also, we ignore the realms
            // boolean b3 = HTTPUtil.equals(a1.getRealm(), a2.getRealm());
            boolean b4 = HTTPUtil.schemeEquals(a1.getScheme(), a2.getScheme());
            if(!(b1 && b2 && b4))
                return false;
        } else if(!a1.equals(a2))
            return false;
        return true;
    }
    */
    static public AuthScope
    fixScopeRealm(AuthScope scope)
    {
        String realm = makerealm(scope);
        return new AuthScope(scope.getHost(), scope.getPort(), realm,
                scope.getScheme());
    }

    static public String makerealm(URI url)
    {
        return makerealm(url.getHost(), url.getPort());
    }

    static public String makerealm(AuthScope scope)
    {
        return makerealm(scope.getHost(), scope.getPort());
    }

    static public String makerealm(String host, int port)
    {
        if(host == null) host = ANY_HOST;
        if(host == ANY_HOST)
            return ANY_REALM;
        String sport = (port <= 0 || port == ANY_PORT) ? "" : String.format("%d", port);
        return host + sport;
    }

}
