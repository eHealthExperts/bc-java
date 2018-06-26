
package org.bouncycastle.eac.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.extensions.TestSetup;
import junit.framework.Test;

class EACTestSetup
    extends TestSetup
{
    public EACTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
