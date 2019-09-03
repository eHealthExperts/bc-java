
package org.bouncycastle.est.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import junit.extensions.TestSetup;
import junit.framework.Test;

class ESTTestSetup
    extends TestSetup
{
    public ESTTestSetup(Test test)
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
