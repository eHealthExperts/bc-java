package org.bouncycastle.jsse.provider;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.tls.DefaultTlsDHConfigVerifier;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.TlsDHConfig;

class ProvDHConfigVerifier
    extends DefaultTlsDHConfigVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.bouncycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.dh.unrestrictedGroups", false);

    private final Object algorithmConstraints;

    ProvDHConfigVerifier(final Object algorithmConstraints) {
        super(provMinimumPrimeBits);
        this.algorithmConstraints = algorithmConstraints;
    }

    @Override
    protected boolean checkGroup(final TlsDHConfig dhConfig) {
        if (this.algorithmConstraints instanceof AlgorithmConstraints) {

            final Set<CryptoPrimitive> primitives = new HashSet<CryptoPrimitive>();
            primitives.add(CryptoPrimitive.KEY_AGREEMENT);

            final String algorithm = "DiffieHellman";
            try {
                final AlgorithmParameters parameters = AlgorithmParameters.getInstance(algorithm);
                final DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig);
                parameters.init(new DHParameterSpec(dhGroup.getP(), dhGroup.getG(), dhGroup.getL()));

                final AlgorithmConstraints constraints = (AlgorithmConstraints) this.algorithmConstraints;
                return provUnrestrictedGroups || (super.checkGroup(dhConfig) && constraints.permits(primitives, algorithm, parameters));
            } catch (final NoSuchAlgorithmException e) {
                throw new SecurityException(e);
            } catch (final InvalidParameterSpecException e) {
                throw new SecurityException(e);
            }
        }

        return provUnrestrictedGroups || super.checkGroup(dhConfig);
    }
}
