package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.crypto.util.EraseUtil;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * Base class for a TlsSecret implementation which captures common code and fields.
 */
public abstract class AbstractTlsSecret
    implements TlsSecret
{
    protected boolean isDestroyed = false;
	protected byte[] data;
    
    /**
     * Base constructor.
     *
     * @param data the byte[] making up the secret value.
     */
    protected AbstractTlsSecret(byte[] data)
    {
        this.data = data;
    }

    public boolean isDestroy() 
    {
    	return isDestroyed || data == null;
    }
    
    protected void checkAlive()
    {
        if (isDestroy())
        {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    protected abstract AbstractTlsCrypto getCrypto();

    public synchronized void destroy()
    {
    	isDestroyed = true;
        if (data != null)
        {
        	EraseUtil.clearByteArray(data);
            this.data = null;
        }
    }

    public synchronized byte[] encrypt(TlsCertificate certificate) throws IOException
    {
        checkAlive();

        return getCrypto().createEncryptor(certificate).encrypt(data, 0, data.length);
    }

    public synchronized byte[] extract()
    {
        checkAlive();
        
        byte[] result = data;
        
        isDestroyed = true;
        this.data = null;
        
        return result;
    }

    public synchronized boolean isAlive()
    {
        return null != data;
    }

    synchronized byte[] copyData()
    {
        return Arrays.clone(data);
    }
    
    @Override
    protected void finalize() throws Throwable 
    {
       super.finalize();
       EraseUtil.clearByteArray(data);
    }
    
}
