
package org.bouncycastle.dvcs.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.extensions.TestSetup;
import junit.framework.Test;

class DVCSTestSetup
    extends TestSetup
{
    public DVCSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
