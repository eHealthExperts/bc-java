package org.bouncycastle.jsse.provider;

import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.DefaultTlsDHGroupVerifier;
import org.bouncycastle.tls.crypto.DHGroup;

class ProvDHGroupVerifier
    extends DefaultTlsDHGroupVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.bouncycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsse.client.dh.unrestrictedGroups", false);

    private final Object algorithmConstraints;

    ProvDHGroupVerifier(final Object algorithmConstraints) {
        super(provMinimumPrimeBits);
        this.algorithmConstraints = algorithmConstraints;
    }

    @Override
    protected boolean checkGroup(DHGroup dhGroup) {
        if (this.algorithmConstraints instanceof AlgorithmConstraints) {

            final Set<CryptoPrimitive> primitives = new HashSet<CryptoPrimitive>();
            primitives.add(CryptoPrimitive.KEY_AGREEMENT);

            final String algorithm = "DiffieHellman";
            try {
                final AlgorithmParameters parameters = AlgorithmParameters.getInstance(algorithm);
                parameters.init(new DHParameterSpec(dhGroup.getP(), dhGroup.getG(), dhGroup.getL()));

                final AlgorithmConstraints constraints = (AlgorithmConstraints) this.algorithmConstraints;
                return provUnrestrictedGroups || (super.checkGroup(dhGroup) && constraints.permits(primitives, algorithm, parameters));
            } catch (final NoSuchAlgorithmException e) {
                throw new SecurityException(e);
            } catch (final InvalidParameterSpecException e) {
                throw new SecurityException(e);
            }
        }
        
        if (this.algorithmConstraints instanceof BCAlgorithmConstraints) {

            final Set<BCCryptoPrimitive> primitives = new HashSet<BCCryptoPrimitive>();
            primitives.add(BCCryptoPrimitive.KEY_AGREEMENT);

            final String algorithm = "DiffieHellman";
            try {
                final AlgorithmParameters parameters = AlgorithmParameters.getInstance(algorithm);
                parameters.init(new DHParameterSpec(dhGroup.getP(), dhGroup.getG(), dhGroup.getL()));

                final BCAlgorithmConstraints constraints = (BCAlgorithmConstraints) this.algorithmConstraints;
                return provUnrestrictedGroups || (super.checkGroup(dhGroup) && constraints.permits(primitives, algorithm, parameters));
            } catch (final NoSuchAlgorithmException e) {
                throw new SecurityException(e);
            } catch (final InvalidParameterSpecException e) {
                throw new SecurityException(e);
            }
        }

        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
