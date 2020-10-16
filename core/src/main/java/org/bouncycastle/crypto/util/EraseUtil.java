package org.bouncycastle.crypto.util;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class EraseUtil {

    private static Logger LOG = java.util.logging.Logger.getLogger(EraseUtil.class.getName());
    
	/** must be equal to the private constant BigInteger#MAX_CONSTANT which is currently 16 */
    private static final int BIGINTEGER_MAX_CONSTANT = 16;

    public static void clearByteArray(final byte[] array) 
    {
        if (array != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.byte.skip") == null) {
    		Arrays.fill(array, (byte) 0);
        }
    }

    public static void clearIntArray(final int[] array) 
    {
        if (array != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.int.skip") == null) 
        {
    		Arrays.fill(array, 0);
        }
    }

    public static void clearLongArray(final long[] array) 
    {
        if (array != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.long.skip") == null) 
        {
    		Arrays.fill(array, 0);
        }
    }

    public static void clearBigInteger(final BigInteger bigInteger) 
    {
    	
        if (bigInteger != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.bigint.skip") == null) 
        {
        	final long value = bigInteger.longValue();
        	
        	// do not clear one of the internal BigInteger constants, which causes heavy side effects
        	// this should be no problem because these constants won't be used as sensitive cryptographic material
        	if (value < -BIGINTEGER_MAX_CONSTANT || value > BIGINTEGER_MAX_CONSTANT)
        	{
        	       	
	            Field declaredField = null;
	            try {
	
	                declaredField = BigInteger.class.getDeclaredField("mag");
	                final boolean accessible = declaredField.isAccessible();
	
	                declaredField.setAccessible(true);
	
	                final int[] array = (int[]) declaredField.get(bigInteger);
	                clearIntArray(array);
	                declaredField.setAccessible(accessible);
	
	            } 
	            catch (Exception e) 
	            {
	                LOG.log(Level.WARNING, "Could not erase BigInteger", e);
	            }
        	}
        }
    }

    public static void clearECFieldElement(final ECFieldElement ecField) {
        if (ecField != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.ecfield.skip") == null) 
        {

            Field declaredField = null;
            try 
            {
                declaredField = ecField.getClass().getDeclaredField("x");
                final boolean accessible = declaredField.isAccessible();

                declaredField.setAccessible(true);

                if (declaredField.getType().isAssignableFrom(BigInteger.class)) 
                {
                    final BigInteger bigInteger = (BigInteger) declaredField.get(ecField);
                    clearBigInteger(bigInteger);
                } 
                else if (declaredField.getType().getSimpleName().equals("LongArray")) 
                {
                    clearBCLongArray(declaredField.get(ecField));
                } 
                else if (declaredField.getType().isArray()) 
                {
                    if (declaredField.getType().getComponentType().getName().equals("int")) 
                    {
                        final int[] array = (int[]) declaredField.get(ecField);
                        clearIntArray(array);
                    } 
                    else if (declaredField.getType().getComponentType().getName().equals("long")) 
                    {
                        final long[] array = (long[]) declaredField.get(ecField);
                        clearLongArray(array);
                    }
                }

                declaredField.setAccessible(accessible);

            } 
            catch (Exception e) 
            {
                LOG.log(Level.WARNING, "Could not erase ECFieldElement", e);
            }
        }
    }

    private static void clearBCLongArray(final Object longArray) 
    {
        if (longArray != null && System.getProperty("bc.erase.skip") == null && System.getProperty("bc.erase.bclong.skip") == null) 
        {
            try 
            {
                final Class<?> c = Class.forName("org.bouncycastle.math.ec.LongArray");
                final Field declaredField = ECPoint.class.getDeclaredField("m_ints");
                final boolean accessible = declaredField.isAccessible();

                declaredField.setAccessible(true);

                final long[] array = (long[]) declaredField.get(longArray);
                clearLongArray(array);

                final ECFieldElement ecField = (ECFieldElement) declaredField.get(longArray);
                clearECFieldElement(ecField);
                declaredField.setAccessible(accessible);

            } 
            catch (Exception e) {
                LOG.log(Level.WARNING, "Could not erase LongArray", e);
            }
        }
    }
}
