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

import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.DeflateDecompressingEntity;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.client.entity.InputStreamFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.params.AllClientPNames;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.UnsupportedCharsetException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipInputStream;

/**
 * A session is encapsulated in an instance of the class HTTPSession.  The
 * encapsulation is with respect to a specific authentication scope, where
 * scope is host+port.  This means that once a session is specified, it is
 * tied permanently to that scope.
 * <p>
 * A Session encapsulate a number of other objects:
 * <ul>
 * <li> An instance of an Apache HttpClient.
 * <li> A http session id
 * <li> A RequestContext object; this also includes authentication:
 * specifically a credential and a credentials provider.
 * <li> Optional principal (not yet implemented)
 * </ul>
 * <p>
 * As a rule, if the client gives an HTTPSession object to the method
 * creation calls to HTTPFactory (e.g. HTTPFactory.Get or HTTPFactory.Post)
 * then that creation call must specify a url that is "compatible" with the
 * scope of the session.  The method url is <it>compatible</i> if its
 * host+port is the same as the session's host+port (=scope) and its scheme is
 * compatible, where e.g. http is compatible with https
 * (see HTTPAuthUtil.scopeCompatible)
 * <p>
 * If the HTTPFactory method creation call does not specify a session
 * object, then one is created (and destroyed) behind the scenes
 * along with the method.
 * <p>
 * Note that the term legalurl in the following code means that the url has
 * reserved characters within identifieers in escaped form. This is
 * particularly and issue for queries. Especially: ?x[0:5] is legal and the
 * square brackets need not be encoded.
 * <p>
 * As of the move to Apache Httpclient 4.4 and later, the underlying
 * HttpClient objects are generally immutable. This means that at least
 * this class (HTTPSession) and the HTTPMethod class must store the
 * relevant info and create the HttpClient and HttpMethod objects
 * dynamically. This also means that when a parameter is changed (Agent,
 * for example), any existing cached HttpClient must be thrown away and
 * reconstructed using the change. As a rule, the HttpClient object will be
 * created at the last minute so that multiple parameter changes can be
 * effected without have to re-create the HttpClient for each parameter
 * change. Also note that the immutable objects will be cached and reused
 * if no parameters are changed.
 * <p>
 * <ul>Authorization</ul>
 * We assume that the session supports two CredentialsProvider instances
 * and that for a our realm, there is only one scheme for accessing it.
 * The two providers are global and local. The global is used for
 * all HTTPSession instances and the local is for a specific instance.
 * <p>
 * <ul>Proxy</ul>
 * We no longer include any proxy support. Instead we assume the user
 * will set the following -D flags:
 * <ul>
 * <li> -Dhttps.proxyHost=<host>
 * <li> -Dhttp.proxyPort=<port>
 * <li> -Djava.net.useSystemProxies(=true)
 * </ul>
 */

public class HTTPSession implements AutoCloseable
{
    //////////////////////////////////////////////////
    // Constants

    // Define all the legal properties
    // From class AllClientPNames
    // To do: AllClientPNames is deprecated, so change all references
    // Use aliases because in httpclient 4.4, AllClientPNames is deprecated

    static public final String ALLOW_CIRCULAR_REDIRECTS = AllClientPNames.ALLOW_CIRCULAR_REDIRECTS;
    static public final String HANDLE_REDIRECTS = AllClientPNames.HANDLE_REDIRECTS;
    static public final String HANDLE_AUTHENTICATION = AllClientPNames.HANDLE_AUTHENTICATION;
    static public final String MAX_REDIRECTS = AllClientPNames.MAX_REDIRECTS;
    static public final String SO_TIMEOUT = AllClientPNames.SO_TIMEOUT;
    static public final String CONN_TIMEOUT = AllClientPNames.CONNECTION_TIMEOUT;
    static public final String USER_AGENT = AllClientPNames.USER_AGENT;

    // Following not from AllClientPNames
    static public final String COOKIE_STORE = org.apache.http.client.protocol.HttpClientContext.COOKIE_STORE;
    static public final String CONN_REQ_TIMEOUT = "http.connection_request.timeout";
    static public final String RETRIES = "http.retries";
    static public final String UNAVAILRETRIES = "http.service_unavailable";

    // Locally defined
    static public final String COMPRESSION = "COMPRESSION";
    static final public String CREDENTIALS = "Credentials";
    static final public String USESESSIONS = "UseSessions";

    // from: http://en.wikipedia.org/wiki/List_of_HTTP_header_fields
    static final public String HEADER_USERAGENT = "User-Agent";
    static final public String ACCEPT_ENCODING = "Accept-Encoding";

    static final int DFALTTHREADCOUNT = 50;
    static final int DFALTREDIRECTS = 25;
    static final int DFALTCONNTIMEOUT = 1 * 60 * 1000; // 1 minutes (60000 milliseconds)
    static final int DFALTCONNREQTIMEOUT = DFALTCONNTIMEOUT;
    static final int DFALTSOTIMEOUT = 5 * 60 * 1000; // 5 minutes (300000 milliseconds)

    static final int DFALTRETRIES = 3;
    static final int DFALTUNAVAILRETRIES = 3;
    static final int DFALTUNAVAILINTERVAL = 3000; // 3 seconds
    static final String DFALTUSERAGENT = "/NetcdfJava/HttpClient4.4";

    static final String[] KNOWNCOMPRESSORS = {"gzip", "deflate"};

    //////////////////////////////////////////////////////////////////////////
    // Type Declaration(s)

    /**
     * Sub-class HashTable<String,Object> for mnemonic convenience
     * and for synchronized access.
     */
    static class Settings extends Hashtable<String, Object>
    {
        public Settings()
        {
        }

        public Set<String>
        getKeys()
        {
            return keySet();
        }

        public Object getParameter(String param)
        {
            return super.get(param);
        }

        public long getIntParameter(String param)
        {
            return (Long) super.get(param);
        }

        public void setParameter(String param, Object value)
        {
            super.put(param, value);
        }

        public Object removeParameter(String param)
        {
            return super.remove(param);
        }

    }

    static enum Methods
    {
        Get("get"), Head("head"), Put("put"), Post("post"), Options("options");
        private final String name;

        Methods(String name)
        {
            this.name = name;
        }

        public String getName()
        {
            return name;
        }
    }

    static class GZIPResponseInterceptor implements HttpResponseInterceptor
    {
        public void process(final HttpResponse response, final HttpContext context)
                throws HttpException, IOException
        {
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                Header ceheader = entity.getContentEncoding();
                if(ceheader != null) {
                    HeaderElement[] codecs = ceheader.getElements();
                    for(HeaderElement h : codecs) {
                        if(h.getName().equalsIgnoreCase("gzip")) {
                            response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        }
    }

    static class DeflateResponseInterceptor implements HttpResponseInterceptor
    {
        public void process(final HttpResponse response, final HttpContext context)
                throws HttpException, IOException
        {
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                Header ceheader = entity.getContentEncoding();
                if(ceheader != null) {
                    HeaderElement[] codecs = ceheader.getElements();
                    for(HeaderElement h : codecs) {
                        if(h.getName().equalsIgnoreCase("deflate")) {
                            response.setEntity(new DeflateDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        }
    }

    static class ZipStreamFactory implements InputStreamFactory
    {
        // InputStreamFactory methods
        @Override
        public InputStream create(InputStream instream)
                throws IOException
        {
            return new ZipInputStream(instream, HTTPUtil.UTF8);
        }
    }

    static class GZIPStreamFactory implements InputStreamFactory
    {
        // InputStreamFactory methods
        @Override
        public InputStream create(InputStream instream)
                throws IOException
        {
            return new GZIPInputStream(instream);
        }
    }

    static class AuthPair
    {
        String scheme = null;
        CredentialsProvider provider = null;

        public AuthPair(String scheme, CredentialsProvider provider)
        {
            this.scheme = scheme;
            this.provider = provider;
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Static variables

    static public org.slf4j.Logger log
            = org.slf4j.LoggerFactory.getLogger(HTTPSession.class);

    static PoolingHttpClientConnectionManager connmgr;

    static Registry<ConnectionSocketFactory> sslregistry = null;


    // Define a settings object to hold all the
    // settable values; there will be one
    // instance for global and one for local.

    static Settings globalsettings;

    // Define interceptor instances
    static List<HttpRequestInterceptor> reqintercepts = new ArrayList<HttpRequestInterceptor>();
    static List<HttpResponseInterceptor> rspintercepts = new ArrayList<HttpResponseInterceptor>();
    // This is a hack to suppress content-encoding headers from request
    static protected HttpResponseInterceptor CEKILL;
    // Debug Header interceptors
    static protected List<HttpRequestInterceptor> dbgreq = new ArrayList<>();
    static protected List<HttpResponseInterceptor> dbgrsp = new ArrayList<>();

    static protected Map<String, InputStreamFactory> contentDecoderMap;

    //public final HttpClientBuilder setContentDecoderRegistry(Map<String,InputStreamFactory> contentDecoderMap)


    // As taken from the command line, usually
    static protected KeyStore keystore = null;
    static protected KeyStore truststore = null;
    static protected String keypassword = null;
    static protected String trustpassword = null;
    static protected SSLConnectionSocketFactory globalsslfactory = null;

    // For debugging
    static protected Boolean globaldebugheaders = null;

    static {
        CEKILL = new HTTPUtil.ContentEncodingInterceptor();
        contentDecoderMap = new HashMap<String, InputStreamFactory>();
        contentDecoderMap.put("zip", new ZipStreamFactory());
        contentDecoderMap.put("gzip", new GZIPStreamFactory());
        // SSL contexts are handled at the global level only
        setGlobalSSLAuth();
        connmgr = new PoolingHttpClientConnectionManager(sslregistry);
        globalsettings = new Settings();
        setDefaults(globalsettings);
        setGlobalUserAgent(DFALTUSERAGENT);
        setGlobalThreadCount(DFALTTHREADCOUNT);
        setGlobalConnectionTimeout(DFALTCONNTIMEOUT);
        setGlobalSoTimeout(DFALTSOTIMEOUT);

    }

    //////////////////////////////////////////////////////////////////////////
    // Static Methods (Mostly global accessors)


    /// Provide defaults for a settings map
    static void setDefaults(Settings props)
    {
        if(false) {// turn off for now
            props.setParameter(HANDLE_AUTHENTICATION, Boolean.TRUE);
        }
        props.setParameter(HANDLE_REDIRECTS, Boolean.TRUE);
        props.setParameter(ALLOW_CIRCULAR_REDIRECTS, Boolean.TRUE);
        props.setParameter(MAX_REDIRECTS, (Integer) DFALTREDIRECTS);
        props.setParameter(SO_TIMEOUT, (Integer) DFALTSOTIMEOUT);
        props.setParameter(CONN_TIMEOUT, (Integer) DFALTCONNTIMEOUT);
        props.setParameter(USER_AGENT, DFALTUSERAGENT);
    }

    static synchronized public Settings getGlobalSettings()
    {
        return globalsettings;
    }

    static synchronized public void setGlobalUserAgent(String userAgent)
    {
        globalsettings.setParameter(USER_AGENT, userAgent);
    }

    static synchronized public String getGlobalUserAgent()
    {
        return (String) globalsettings.getParameter(USER_AGENT);
    }

    static synchronized public void setGlobalThreadCount(int nthreads)
    {
        connmgr.setMaxTotal(nthreads);
        connmgr.setDefaultMaxPerRoute(nthreads);
    }

    // Alias
    static public void setGlobalMaxConnections(int nthreads)
    {
        setGlobalThreadCount(nthreads);
    }

    static synchronized public int getGlobalThreadCount()
    {
        return connmgr.getMaxTotal();
    }

    // Timeouts

    static synchronized public void setGlobalConnectionTimeout(int timeout)
    {
        if(timeout >= 0) globalsettings.setParameter(CONN_TIMEOUT, (Integer) timeout);
    }

    static synchronized public void setGlobalSoTimeout(int timeout)
    {
        if(timeout >= 0) globalsettings.setParameter(SO_TIMEOUT, (Integer) timeout);
    }

    // Compression

    static synchronized public void
    setGlobalCompression()
    {
        globalsettings.setParameter(COMPRESSION, "gzip,deflate");
        HttpResponseInterceptor hrsi = new GZIPResponseInterceptor();
        rspintercepts.add(hrsi);
        hrsi = new DeflateResponseInterceptor();
        rspintercepts.add(hrsi);
    }

    //////////////////////////////////////////////////
    // Authorization

    /**
     * Assumes that the scheme here is BASIC
     *
     * @param provider
     * @throws HTTPException
     */
    static public void
    setGlobalCredentialsProvider(CredentialsProvider provider)
            throws HTTPException
    {
        if(provider == null) throw new IllegalArgumentException("null argument");
        setGlobalCredentialsProvider(provider, AuthSchemes.BASIC);
    }

    /**
     * It is convenient to be able to directly set the Credentials
     * (not the provider) when those credentials are fixed.
     *
     * @param creds
     * @throws HTTPException
     */
    static public void
    setGlobalCredentials(Credentials creds)
            throws HTTPException
    {
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setGlobalCredentialsProvider(provider);
    }

    /**
     * Ideally, it would nice if one could get the scheme
     * from the Credentials/CredentialsProvider, but no.
     */
    static public void
    setGlobalCredentialsProvider(CredentialsProvider provider, String scheme)
            throws HTTPException
    {
        if(provider == null || scheme == null)
            throw new IllegalArgumentException("null argument");
        globalsettings.setParameter(CREDENTIALS, new AuthPair(scheme, provider));
    }

    /**
     * Following are for back compatibility
     */

    @Deprecated
    static public void
    setGlobalCredentialsProvider(AuthScope scope, CredentialsProvider provider)
            throws HTTPException
    {
        setGlobalCredentialsProvider(provider);
    }

    @Deprecated
    static public void
    setGlobalCredentialsProvider(String url, CredentialsProvider provider)
            throws HTTPException
    {
        if(url == null || provider == null)
            throw new IllegalArgumentException("null argument");
        AuthScope scope = HTTPAuthUtil.uriToScope(url, AuthSchemes.BASIC);
        setGlobalCredentialsProvider(scope, provider);
    }

    @Deprecated
    static public void
    setGlobalCredentials(String url, Credentials creds)
            throws HTTPException
    {
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setGlobalCredentialsProvider(url, provider);
    }

    //////////////////////////////////////////////////
    // Static Utility functions

    static public String getCanonicalURL(String legalurl)
    {
        if(legalurl == null) return null;
        int index = legalurl.indexOf('?');
        if(index >= 0) legalurl = legalurl.substring(0, index);
        // remove any trailing extension
        //index = legalurl.lastIndexOf('.');
        //if(index >= 0) legalurl = legalurl.substring(0,index);
        return canonicalpath(legalurl);
    }

    /**
     * Convert path to use '/' consistently and
     * to remove any trailing '/'
     *
     * @param path convert this path
     * @return canonicalized version
     */
    static public String canonicalpath(String path)
    {
        if(path == null) return null;
        path = path.replace('\\', '/');
        if(path.endsWith("/"))
            path = path.substring(0, path.length() - 1);
        return path;
    }

    static public String
    getUrlAsString(String url) throws HTTPException
    {
        try (
                HTTPMethod m = HTTPFactory.Get(url);) {
            int status = m.execute();
            String content = null;
            if(status == 200) {
                content = m.getResponseAsString();
            }
            return content;
        }
    }

    static public int
    putUrlAsString(String content, String url) throws HTTPException
    {
        int status = 0;
        try {
            try (HTTPMethod m = HTTPFactory.Put(url)) {
                m.setRequestContent(new StringEntity(content,
                        ContentType.create("application/text", "UTF-8")));
                status = m.execute();
            }
        } catch (UnsupportedCharsetException uce) {
            throw new HTTPException(uce);
        }
        return status;
    }

    static protected String
    getstorepath(String prefix)
    {
        String path = System.getProperty(prefix + "store");
        if(path != null) {
            path = path.trim();
            if(path.length() == 0) path = null;
        }
        return path;
    }

    static protected String
    getpassword(String prefix)
    {
        String password = System.getProperty(prefix + "storepassword");
        if(password != null) {
            password = password.trim();
            if(password.length() == 0) password = null;
        }
        return password;
    }

    static protected String
    cleanproperty(String property)
    {
        String value = System.getProperty(property);
        if(value != null) {
            value = value.trim();
            if(value.length() == 0) value = null;
        }
        return value;
    }

    // Provide for backward compatibility
    // through the -D properties

    static synchronized void
    setGlobalSSLAuth()
    {
        RegistryBuilder rb = RegistryBuilder.<ConnectionSocketFactory>create();

        String keypassword = cleanproperty("keystorepassword");
        String keypath = cleanproperty("keystore");
        String trustpassword = cleanproperty("truststorepassword");
        String trustpath = cleanproperty("truststore");

        if(keypath == null && trustpath == null) {
            HTTPSession.log.info(String.format("HTTPSession: no trust/key store properties found"));
            sslregistry = rb.build();
            return;
        }

        // load the stores
        try {
            if(trustpath != null) {
                truststore = KeyStore.getInstance(KeyStore.getDefaultType());
                try (FileInputStream instream = new FileInputStream(new File(trustpath))) {
                    truststore.load(instream, trustpassword.toCharArray());
                }
            }
            if(keypath != null) {
                keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                try (FileInputStream instream = new FileInputStream(new File(keypath))) {
                    keystore.load(instream, keypassword.toCharArray());
                }
            }
        } catch (IOException
                | NoSuchAlgorithmException
                | CertificateException
                | KeyStoreException ex) {
            log.error("Illegal -D keystore parameters: " + ex.getMessage());
        }
        try {
            // set up the global info
            SSLContextBuilder sslbuilder = SSLContexts.custom();
            HostnameVerifier verifier = new HostnameVerifier()
            {
                public boolean verify(String hostname, SSLSession session)
                {
                    return true;
                }
            };

            if(truststore != null)
                sslbuilder.loadTrustMaterial(truststore, new TrustSelfSignedStrategy());
            if(keystore != null)
                sslbuilder.loadKeyMaterial(keystore, keypassword.toCharArray());
            SSLContext scxt = sslbuilder.build();
            globalsslfactory = new SSLConnectionSocketFactory(scxt, verifier);
            rb.register("https", globalsslfactory);

            sslregistry = rb.build();
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | KeyManagementException
                | UnrecoverableEntryException e) {
            log.error("Failed to set key/trust store(s): " + e.getMessage());
        }
    }

    //////////////////////////////////////////////////
    // Instance variables


    // Currently, the granularity of authorization is host+port.
    protected String sessionURL = null; // This is a real url or one from the scope
    protected URI scopeURI = null;
    protected AuthScope scope = null; /* from scopeURI  */
    protected boolean closed = false;

    protected List<ucar.httpservices.HTTPMethod> methodList = new Vector<HTTPMethod>();
    protected String identifier = "Session";
    protected Settings localsettings = new Settings();

    // We currently only allow the use of global interceptors
    protected List<Object> intercepts = new ArrayList<Object>(); // current set of interceptors;

    // This context is re-used over all method executions so that we maintain
    // cookies, credentials, etc.
    // But we do need away to clear so that e.g. we can clear credentials cache
    protected HttpClientContext sessioncontext = HttpClientContext.create();

    // cached and recreated as needed
    protected boolean cachevalid = false; // Are cached items up-to-date?
    protected CloseableHttpClient cachedclient = null;
    protected URI requestURI = null;  // full uri from the HTTPMethod call

    //////////////////////////////////////////////////
    // Constructor(s)

    protected HTTPSession()
            throws HTTPException
    {
    }

    public HTTPSession(String host, int port)
            throws HTTPException
    {
        init(new AuthScope(host, port, HTTPAuthUtil.makerealm(host, port)));
    }


    public HTTPSession(String url)
            throws HTTPException
    {
        if(url == null || url.length() == 0)
            throw new HTTPException("HTTPSession(): empty URL not allowed");
        try {
            HTTPUtil.parseToURI(url); /// validate
        } catch (URISyntaxException mue) {
            throw new HTTPException("Malformed URL: " + url, mue);
        }
        // Make sure url has leading protocol
        if(!url.matches("^[a-zZ-Z0-9+.-]+:.*$"))
            url = "http:" + url; // try to make it parseable
        this.sessionURL = url;
        init(HTTPAuthUtil.uriToScope(url, null));
    }

    public HTTPSession(AuthScope scope)
            throws HTTPException
    {
        init(scope);
    }

    protected void init(AuthScope scope)
            throws HTTPException
    {
        if(scope == null) throw new IllegalArgumentException("null argument");
        this.scope = scope;
        this.scopeURI = HTTPAuthUtil.scopeToURI(scope);
        this.cachevalid = false; // Force build on first use
        this.sessioncontext.setCookieStore(new BasicCookieStore());
        this.sessioncontext.setAttribute(HttpClientContext.AUTH_CACHE, new BasicAuthCache());
    }

    //////////////////////////////////////////////////
    // Interceptors

    public void
    setCompression(String compressors)
    {
        // Syntactic check of compressors
        Set<String> cset = new HashSet<>();
        String[] pieces = compressors.split("[ \t]*[,][ \t]*");
        for(String p : pieces) {
            for(String c : KNOWNCOMPRESSORS) {
                if(p.equalsIgnoreCase(c)) {
                    cset.add(c);
                    break;
                }
            }
        }
        StringBuilder buf = new StringBuilder();
        for(String s : cset) {
            if(buf.length() > 0) buf.append(",");
            buf.append(s);
        }
        if(localsettings.getParameter(COMPRESSION) != null)
            removeCompression();
        localsettings.setParameter(COMPRESSION, buf.toString());
        HttpResponseInterceptor hrsi = new GZIPResponseInterceptor();
//        rspintercepts.add(hrsi);
        hrsi = new DeflateResponseInterceptor();
//        rspintercepts.add(hrsi);
    }

    public void
    removeCompression()
    {
        if(localsettings.removeParameter(COMPRESSION) != null) {
            for(int i = rspintercepts.size() - 1; i >= 0; i--) { // walk backwards
                HttpResponseInterceptor hrsi = rspintercepts.get(i);
                if(hrsi instanceof GZIPResponseInterceptor
                        || hrsi instanceof DeflateResponseInterceptor)
                    rspintercepts.remove(i);
            }
        }
    }

    protected void
    setInterceptors(HttpClientBuilder cb)
    {
        for(HttpRequestInterceptor hrq : reqintercepts) {
            cb.addInterceptorLast(hrq);
        }
        for(HttpResponseInterceptor hrs : rspintercepts) {
            cb.addInterceptorLast(hrs);
        }
        // Add debug interceptors
        for(HttpRequestInterceptor hrq : dbgreq) {
            cb.addInterceptorFirst(hrq);
        }
        for(HttpResponseInterceptor hrs : dbgrsp) {
            cb.addInterceptorFirst(hrs);
        }
        // Hack: add Content-Encoding suppressor
        cb.addInterceptorFirst(CEKILL);
    }

    //////////////////////////////////////////////////
    // Accessor(s)

    public Settings getSettings()
    {
        return localsettings;
    }

    public AuthScope getScope()
    {
        return this.scope;
    }

    public String getSessionURL()
    {
        return this.sessionURL;
    }

    /**
     * Extract the sessionid cookie value
     *
     * @return sessionid string
     */
    public String getSessionID()
    {
        String sid = null;
        String jsid = null;
        List<Cookie> cookies = this.sessioncontext.getCookieStore().getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equalsIgnoreCase("sessionid"))
                sid = cookie.getValue();
            if(cookie.getName().equalsIgnoreCase("jsessionid"))
                jsid = cookie.getValue();
        }
        return (sid == null ? jsid : sid);
    }

    public void setUserAgent(String agent)
    {
        if(agent == null || agent.length() == 0) throw new IllegalArgumentException("null argument");
        localsettings.setParameter(USER_AGENT, agent);
        this.cachevalid = false;
    }

    public void setSoTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException("setSoTimeout");
        localsettings.setParameter(SO_TIMEOUT, timeout);
        this.cachevalid = false;
    }

    public void setConnectionTimeout(int timeout)
    {
        if(timeout <= 0)
            throw new IllegalArgumentException("setConnectionTImeout");
        localsettings.setParameter(CONN_TIMEOUT, timeout);
        localsettings.setParameter(CONN_REQ_TIMEOUT, timeout);
        this.cachevalid = false;
    }

    /**
     * Set the max number of redirects to follow
     *
     * @param n
     */
    public void setMaxRedirects(int n)
    {
        if(n < 0) //validate
            throw new IllegalArgumentException("setMaxRedirects");
        localsettings.setParameter(MAX_REDIRECTS, n);
        this.cachevalid = false;
    }

    /**
     * Enable/disable redirection following
     * Default is yes.
     */
    public void setFollowRedirects(boolean tf)
    {
        localsettings.setParameter(HANDLE_REDIRECTS, (Boolean) tf);
        this.cachevalid = false;
    }

    /**
     * Should we use sessionid's?
     *
     * @param tf
     */
    public void setUseSessions(boolean tf)
    {
        localsettings.setParameter(USESESSIONS, (Boolean) tf);
        this.cachevalid = false;
    }

    public void
    clearCookies()
    {
        BasicCookieStore cookies = (BasicCookieStore) this.sessioncontext.getCookieStore();
        if(cookies != null) cookies.clear();
    }

    public void
    clearCredentialsCache()
    {
        BasicAuthCache ac = (BasicAuthCache) this.sessioncontext.getAttribute(HttpClientContext.AUTH_CACHE);
        if(ac != null) ac.clear();
    }

    // make package specific

    HttpClient
    getClient()
    {
        return this.cachedclient;
    }

    HttpClientContext
    getExecutionContext()
    {
        return this.sessioncontext;
    }

    //////////////////////////////////////////////////

    /**
     * Close the session. This implies closing
     * any open methods.
     */

    synchronized public void close()
    {
        if(this.closed)
            return; // multiple calls ok
        while(methodList.size() > 0) {
            HTTPMethod m = methodList.get(0);
            m.close(); // forcibly close; will invoke removemethod().
        }
        closed = true;
    }

    public List<Cookie> getCookies()
    {
        if(this.sessioncontext == null)
            return null;
        List<Cookie> cookies = this.sessioncontext.getCookieStore().getCookies();
        return cookies;
    }

    synchronized void addMethod(HTTPMethod m)
    {
        if(!methodList.contains(m))
            methodList.add(m);
    }

    synchronized void removeMethod(HTTPMethod m)
    {
        methodList.remove(m);
    }


    //////////////////////////////////////////////////
    // Authorization
    // per-session versions of the global accessors

    /**
     * @param provider
     * @throws HTTPException
     */
    public void
    setCredentialsProvider(CredentialsProvider provider)
            throws HTTPException
    {
        if(provider == null) throw new IllegalArgumentException("null argument");
        setCredentialsProvider(provider, AuthSchemes.BASIC);
    }

    /**
     * It is convenient to be able to directly set the Credentials
     * (not the provider) when those credentials are fixed.
     *
     * @param creds
     * @throws HTTPException
     */
    public void
    setCredentials(Credentials creds)
            throws HTTPException
    {
        if(creds == null) throw new IllegalArgumentException("null argument");
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setCredentialsProvider(provider);
    }

    public void
    setCredentialsProvider(CredentialsProvider provider, String scheme)
            throws HTTPException
    {
        if(provider == null || scheme == null) throw new IllegalArgumentException("null argument");
        localsettings.setParameter(CREDENTIALS, new AuthPair(scheme, provider));
    }

    /**
     * For backward compatibility
     */

    @Deprecated
    public void
    setCredentials(String url, Credentials creds)
            throws HTTPException
    {
        if(url == null || creds == null)
            throw new IllegalArgumentException("null argument");
        CredentialsProvider provider = new HTTPConstantProvider(creds);
        setCredentialsProvider(url, provider);
    }

    @Deprecated
    public void
    setCredentialsProvider(String url, CredentialsProvider provider)
            throws HTTPException
    {
        if(url == null || provider == null)
            throw new IllegalArgumentException("null argument");
        AuthScope scope = HTTPAuthUtil.uriToScope(url, AuthSchemes.BASIC);
        setCredentialsProvider(scope, provider);
    }

    @Deprecated
    public void
    setCredentialsProvider(AuthScope scope, CredentialsProvider provider)
            throws HTTPException
    {
        if(provider == null || scope == null || scope.getScheme() == null)
            throw new IllegalArgumentException("null argument");
        setCredentialsProvider(provider);
    }

    //////////////////////////////////////////////////
    // Execution (do an actual execution)

    // Package visible

    /**
     * Called primarily from HTTPMethod to do the bulk
     * of the execution. Assumes HTTPMethod
     * has inserted its headers into request.
     *
     * @param method
     * @param methoduri
     * @param rb
     * @return CloseableHttpResponse
     * @throws HTTPException
     */

    CloseableHttpResponse
    execute(HTTPMethod method, URI methoduri, RequestBuilder rb)
            throws HTTPException
    {
        this.requestURI = methoduri;
        RequestConfig.Builder rcb = RequestConfig.custom();
        HttpHost target = HTTPAuthUtil.scopeToHost(this.scope,
                HTTPAuthUtil.uriToScope(methoduri,HTTPAuthUtil.ANY_SCHEME));

        synchronized (this) {// keep coverity happy
            //Merge Settings;
            Settings merged = HTTPUtil.merge(globalsettings, localsettings);
            configureRequest(rb, rcb, merged);
            if(!this.cachevalid) {
                HttpClientBuilder cb = HttpClients.custom();
                configClient(cb, merged);
                setAuthentication(cb, merged);
                this.cachedclient = cb.build();
                this.cachevalid = true;
            }
        }
        // Save relevant info in the HTTPMethod object
        CloseableHttpResponse response;
        try {
            HttpUriRequest hur = rb.build();
            response = cachedclient.execute(target, hur, this.sessioncontext);
        } catch (IOException ioe) {
            throw new HTTPException(ioe);
        }
        return response;
    }

    protected void
    configureRequest(RequestBuilder rb, RequestConfig.Builder rcb, Settings settings)
            throws HTTPException
    {
        // Configure the RequestConfig
        for(String key : settings.getKeys()) {
            Object value = settings.getParameter(key);
            boolean tf = (value instanceof Boolean ? (Boolean) value : false);
            if(key.equals(ALLOW_CIRCULAR_REDIRECTS)) {
                rcb.setCircularRedirectsAllowed(tf);
            } else if(key.equals(HANDLE_REDIRECTS)) {
                rcb.setRedirectsEnabled(tf);
                rcb.setRelativeRedirectsAllowed(tf);
            } else if(key.equals(MAX_REDIRECTS)) {
                rcb.setMaxRedirects((Integer) value);
            } else if(key.equals(SO_TIMEOUT)) {
                rcb.setSocketTimeout((Integer) value);
            } else if(key.equals(CONN_TIMEOUT)) {
                rcb.setConnectTimeout((Integer) value);
            } else if(key.equals(CONN_REQ_TIMEOUT)) {
                rcb.setConnectionRequestTimeout((Integer) value);
            } /* else ignore */
        }
        rb.setConfig(rcb.build());
    }

    protected void
    configClient(HttpClientBuilder cb, Settings settings)
            throws HTTPException
    {
        cb.useSystemProperties();
        String agent = (String) settings.get(USER_AGENT);
        if(agent != null)
            cb.setUserAgent(agent);
        setInterceptors(cb);
        cb.setContentDecoderRegistry(contentDecoderMap);
    }

    /**
     * Handle authentication.
     *
     * @param cb
     * @param rb
     * @param settings
     * @throws HTTPException
     */

    synchronized protected void
    setAuthentication(HttpClientBuilder cb, Settings settings)
            throws HTTPException
    {
        // Get the appropriate AuthPair.
        AuthPair pair = (AuthPair) globalsettings.get(CREDENTIALS);
        if(pair != null)
            cb.setDefaultCredentialsProvider(pair.provider);
        pair = (AuthPair) localsettings.get(CREDENTIALS);
        if(pair != null)
            this.sessioncontext.setCredentialsProvider(pair.provider);
        cb.setSSLSocketFactory(globalsslfactory);
    }

    //////////////////////////////////////////////////
    // Testing support

    // Expose the state for testing purposes
    synchronized public boolean isClosed()
    {
        return this.closed;
    }

    synchronized public int getMethodcount()
    {
        return methodList.size();
    }

    //////////////////////////////////////////////////
    // Debug interface

    // Provide a way to kill everything at the end of a Test

    // When testing, we need to be able to clean up
    // all existing sessions because JUnit can run all
    // test within a single jvm.
    static List<HTTPSession> sessionList = null; // List of all HTTPSession instances

    // only used when testing flag is set
    static public boolean TESTING = false; // set to true during testing, should be false otherwise

    static protected synchronized void kill()
    {
        if(sessionList != null) {
            for(HTTPSession session : sessionList) {
                session.close();
            }
            sessionList.clear();
            // Rebuild the connection manager
            connmgr.shutdown();
            connmgr = new PoolingHttpClientConnectionManager(sslregistry);
            setGlobalThreadCount(DFALTTHREADCOUNT);
        }
    }

    // If we are testing, then track the sessions for kill
    static protected synchronized void track(HTTPSession session)
    {
        if(sessionList == null)
            sessionList = new ArrayList<HTTPSession>();
        sessionList.add(session);
    }

    static synchronized public void debugHeaders(boolean print)
    {
        HTTPUtil.InterceptRequest rq = new HTTPUtil.InterceptRequest();
        HTTPUtil.InterceptResponse rs = new HTTPUtil.InterceptResponse();
        rq.setPrint(print);
        rs.setPrint(print);
        /* remove any previous */
        for(int i = reqintercepts.size() - 1; i >= 0; i--) {
            HttpRequestInterceptor hr = reqintercepts.get(i);
            if(hr instanceof HTTPUtil.InterceptCommon)
                reqintercepts.remove(i);
        }
        for(int i = rspintercepts.size() - 1; i >= 0; i--) {
            HttpResponseInterceptor hr = rspintercepts.get(i);
            if(hr instanceof HTTPUtil.InterceptCommon)
                rspintercepts.remove(i);
        }
        reqintercepts.add(rq);
        rspintercepts.add(rs);
    }

    public static void
    debugReset()
    {
        for(HttpRequestInterceptor hri : reqintercepts) {
            if(hri instanceof HTTPUtil.InterceptCommon)
                ((HTTPUtil.InterceptCommon) hri).clear();
        }
    }

    public static HTTPUtil.InterceptRequest
    debugRequestInterceptor()
    {
        for(HttpRequestInterceptor hri : reqintercepts) {
            if(hri instanceof HTTPUtil.InterceptRequest)
                return ((HTTPUtil.InterceptRequest) hri);
        }
        return null;
    }

    public static HTTPUtil.InterceptResponse
    debugResponseInterceptor()
    {
        for(HttpResponseInterceptor hri : rspintercepts) {
            if(hri instanceof HTTPUtil.InterceptResponse)
                return ((HTTPUtil.InterceptResponse) hri);
        }
        return null;
    }

}
