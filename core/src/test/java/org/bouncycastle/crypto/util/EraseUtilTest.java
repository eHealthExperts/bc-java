package org.bouncycastle.crypto.util;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import junit.framework.Assert;

public class EraseUtilTest {

	@Test
	public void testBigIntegerErasure() {
		final long value = 10;
		
		final BigInteger first = BigInteger.valueOf(value);
		assertEquals(value, first.longValue());
		
		EraseUtil.clearBigInteger(first);
		
		final BigInteger secound = BigInteger.valueOf(value);
		assertEquals(value, secound.longValue());

	}

}
