package org.bouncycastle.crypto.params;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.util.EraseUtil;

public class KeyParameter
    implements CipherParameters, Destroyable
{
    private byte[]  key;

    public KeyParameter(
        byte[]  key)
    {
        this(key, 0, key.length);
    }

    public KeyParameter(
        byte[]  key,
        int     keyOff,
        int     keyLen)
    {
        this.key = new byte[keyLen];

        System.arraycopy(key, keyOff, this.key, 0, keyLen);
    }

    public byte[] getKey()
    {
        return key;
    }
    
    public void destroy() throws DestroyFailedException {
    	EraseUtil.clearByteArray(key);
    }
    
    @Override
    protected void finalize() throws Throwable
    {	
    	super.finalize();
    	EraseUtil.clearByteArray(key);
    }
}
