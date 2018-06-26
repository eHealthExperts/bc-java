package org.bouncycastle.operator.jcajce;

import java.security.Key;

import org.bouncycastle.jcajce.provider.asymmetric.DestroyableSecretKeySpec;
import org.bouncycastle.operator.GenericKey;

class OperatorUtils
{
    static Key getJceKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return (Key)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new DestroyableSecretKeySpec((byte[])key.getRepresentation(), "ENC");
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}