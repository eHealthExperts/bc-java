package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.bouncycastle.crypto.util.EraseUtil;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl package.
 */
public abstract class AbstractTlsCrypto implements TlsCrypto {
    /**
     * Adopt the passed in secret, creating a new copy of it..
     *
     * @param secret
     *            the secret to make a copy of.
     * @return a TlsSecret based the original secret.
     */
    public TlsSecret adoptSecret(final TlsSecret secret) {
        // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
        if (secret instanceof AbstractTlsSecret) {
            final AbstractTlsSecret sec = (AbstractTlsSecret) secret;

            final byte[] copyData = sec.copyData();
            final TlsSecret ret = this.createSecret(copyData);
            EraseUtil.clearByteArray(copyData);
            return ret;
        }

        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }

    public TlsDHConfig createDHConfig(final int selectedCipherSuite, final int[] clientSupportedGroups) throws GeneralSecurityException {
        final int minimumFiniteFieldBits = TlsDHUtils.getMinimumFiniteFieldBits(selectedCipherSuite);

        TlsDHConfig dhConfig = null;
        if (clientSupportedGroups == null) {
            dhConfig = this.selectDefaultDHConfig(minimumFiniteFieldBits);
        } else {
            // Try to find a supported named group of the required size from the client's list.
            for (final int namedGroup : clientSupportedGroups) {
                if (NamedGroup.getFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits) {
                    dhConfig = new TlsDHConfig(namedGroup);
                }
            }
        }

        if (dhConfig == null) {
            throw new GeneralSecurityException("Count not create a TlsDHConfig!");
        }
        return dhConfig;
    }

    protected TlsDHConfig selectDefaultDHConfig(final int minimumFiniteFieldBits) {
        final int namedGroup = minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
                : minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
                        : minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096 : minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144 : minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192 : -1;

        return TlsDHUtils.createNamedDHConfig(namedGroup);
    }

    /**
     * Create a cipher for the specified encryption and MAC algorithms.
     * <p>
     * See enumeration classes {@link EncryptionAlgorithm}, {@link MACAlgorithm} for appropriate argument values.
     * </p>
     *
     * @param cryptoParams
     *            context specific parameters.
     * @param encryptionAlgorithm
     *            the encryption algorithm to be employed by the cipher.
     * @param macAlgorithm
     *            the MAC algorithm to be employed by the cipher.
     * @return a {@link TlsCipher} implementing the encryption and MAC algorithm.
     * @throws IOException
     */
    protected abstract TlsCipher createCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm) throws IOException;

    /**
     * Return an encryptor based on the public key in certificate.
     *
     * @param certificate
     *            the certificate carrying the public key.
     * @return a TlsEncryptor based on the certificate's public key.
     */
    protected abstract TlsEncryptor createEncryptor(TlsCertificate certificate) throws IOException;
}
