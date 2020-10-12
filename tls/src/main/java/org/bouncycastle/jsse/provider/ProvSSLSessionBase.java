package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;

abstract class ProvSSLSessionBase
    extends BCExtendedSSLSession
{
    protected final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<String, Object>());

    protected ProvSSLSessionContext sslSessionContext;
    protected final boolean isFips;
    protected final JcaTlsCrypto crypto;
    protected final String peerHost;
    protected final int peerPort;
    protected final long creationTime;
    protected final SSLSession exportSSLSession;

    protected long lastAccessedTime;

    ProvSSLSessionBase(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort)
    {
        this.sslSessionContext = sslSessionContext;
        this.isFips = (null == sslSessionContext) ? false : sslSessionContext.getSSLContext().isFips();
        this.crypto = (null == sslSessionContext) ? null : sslSessionContext.getCrypto();
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.creationTime = System.currentTimeMillis();
        this.exportSSLSession = SSLSessionUtil.exportSSLSession(this);
        this.lastAccessedTime = creationTime;
    }

    protected abstract int getCipherSuiteTLS();

    protected abstract byte[] getIDArray();

    protected abstract JsseSecurityParameters getJsseSecurityParameters();

    protected abstract JsseSessionParameters getJsseSessionParameters();

    protected abstract org.bouncycastle.tls.Certificate getLocalCertificateTLS();

    protected abstract org.bouncycastle.tls.Certificate getPeerCertificateTLS();

    protected abstract ProtocolVersion getProtocolTLS();

    SSLSession getExportSSLSession()
    {
        return exportSSLSession;
    }

    synchronized void accessedAt(long accessTime)
    {
        this.lastAccessedTime = Math.max(lastAccessedTime, accessTime);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof ProvSSLSessionBase))
        {
            return false;
        }

        ProvSSLSessionBase other = (ProvSSLSessionBase)obj;
        return Arrays.areEqual(getIDArray(), other.getIDArray());
    }

    public int getApplicationBufferSize()
    {
        // TODO[jsse] See comments for getPacketBufferSize
        return 1 << 14; 
    }

    public String getCipherSuite()
    {
        return ProvSSLContextSpi.getCipherSuiteName(getCipherSuiteTLS());
    }

    public long getCreationTime()
    {
        return creationTime;
    }

    public byte[] getId()
    {
        byte[] id = getIDArray();
        return TlsUtils.isNullOrEmpty(id) ? TlsUtils.EMPTY_BYTES : id.clone();
    }

    public long getLastAccessedTime()
    {
        return lastAccessedTime;
    }

    public Certificate[] getLocalCertificates()
    {
        if (null != crypto)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(crypto, getLocalCertificateTLS());
            if (null != chain && chain.length > 0)
            {
                return chain;
            }
        }

        return null;
    }

    public Principal getLocalPrincipal()
    {
        if (null != crypto)
        {
            return JsseUtils.getSubject(crypto, getLocalCertificateTLS());
        }

        return null;
    }

    public int getPacketBufferSize()
    {
        /*
         * TODO[jsse] This is the maximum possible per RFC (but see jsse.SSLEngine.acceptLargeFragments System property).
         * It would be nice to dynamically check with the underlying RecordStream, which might know a tighter limit, e.g.
         * when the max_fragment_length extension has been negotiated. (Compression is not supported, so no expansion needed).
         */
        // Header size + Fragment length limit + Cipher expansion
//        return RecordFormat.FRAGMENT_OFFSET + (1 << 14) + 1024;

        /*
         * Worst case accounts for possible application data splitting (before TLS 1.1)
         */
        return (1 << 14) + 1 + 2 * (RecordFormat.FRAGMENT_OFFSET + 1024);
    }

    @SuppressWarnings("deprecation")
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        if (isFips)
        {
            throw new UnsupportedOperationException();
        }

        /*
         * "Note: this method exists for compatibility with previous releases. New applications
         * should use getPeerCertificates() instead."
         */
        Certificate[] peerCertificates = getPeerCertificates();
        try
        {
            javax.security.cert.X509Certificate[] chain = new javax.security.cert.X509Certificate[peerCertificates.length];
            for (int i = 0; i < peerCertificates.length; ++i)
            {
                chain[i] = javax.security.cert.X509Certificate.getInstance(peerCertificates[i].getEncoded());
            }
            return chain;
        }
        catch (Exception e)
        {
            throw new SSLPeerUnverifiedException(e.getMessage());
        }
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        if (null != crypto)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(crypto, getPeerCertificateTLS());
            if (null != chain && chain.length > 0)
            {
                return chain;
            }
        }

        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        if (null != crypto)
        {
            X500Principal principal = JsseUtils.getSubject(crypto, getPeerCertificateTLS());
            if (null != principal)
            {
                return principal;
            }
        }

        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public String getPeerHost()
    {
        return peerHost;
    }

    public int getPeerPort()
    {
        return peerPort;
    }

    public String getProtocol()
    {
        return ProvSSLContextSpi.getProtocolVersionName(getProtocolTLS());
    }

    public SSLSessionContext getSessionContext()
    {
        SecurityManager sm = System.getSecurityManager();
        if (null != sm)
        {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }

        return sslSessionContext;
    }

    public Object getValue(String name)
    {
        return valueMap.get(name);
    }

    public String[] getValueNames()
    {
        synchronized (valueMap)
        {
            return valueMap.keySet().toArray(new String[valueMap.size()]);
        }
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(getIDArray());
    }

    public synchronized void invalidate()
    {
        // NOTE: The NULL_SESSION never actually gets invalidated (consistent with SunJSSE)

        if (null != sslSessionContext)
        {
            sslSessionContext.removeSession(getIDArray());

            this.sslSessionContext = null;
        }
    }

    public synchronized boolean isValid()
    {
        if (null == sslSessionContext)
        {
            return false;
        }

        // TODO[tls13] TLS 1.3 doesn't need a session ID for resumption?
//        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(getProtocolTLS()))
//        {
//            return true;
//        }

        return !TlsUtils.isNullOrEmpty(getIDArray());
    }

    public void putValue(String name, Object value)
    {
        notifyUnbound(name, valueMap.put(name, value));
        notifyBound(name, value);
    }

    public void removeValue(String name)
    {
        notifyUnbound(name, valueMap.remove(name));
    }

    @Override
    public String toString()
    {
        return "Session(" + getCreationTime() + "|" + getCipherSuite() + ")";
    }

    protected void notifyBound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            ((SSLSessionBindingListener)value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    protected void notifyUnbound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            ((SSLSessionBindingListener)value).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }
}
