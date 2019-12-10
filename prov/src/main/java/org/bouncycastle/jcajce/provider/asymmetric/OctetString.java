package org.bouncycastle.jcajce.provider.asymmetric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import org.bouncycastle.crypto.util.EraseUtil;

/**
 * Kapselt eine Bytesequenz mit einem intern verwalteten {@link ByteBuffer} und
 * bietet darüber hinaus die Möglichkeit, diese sicher zu löschen (mit Nullen zu
 * überschreiben). Primäres Ziel ist es dabei, die Bytesequenz möglichs nicht
 * herauszugeben und alle benötigten Operationen in dieser Klasse zu kapseln.
 *
 */
public class OctetString implements Destroyable {

	private static Logger LOG = Logger.getLogger(OctetString.class.getName());

	private final ByteBuffer value;
	private final AtomicBoolean destroyed;

	/**
	 * Erzeugt eine neue Instanz ohne Inhalt.
	 */
	public OctetString() {
		this.value = ByteBuffer.allocateDirect(0);
		this.destroyed = new AtomicBoolean(false);
	}

	/**
	 * Erzeugt eine Instanz durch Kopie der übergebenen Bytess.
	 *
	 * @param bytes
	 *            zu kopierende Bytes
	 */
	public OctetString(final byte... bytes) {
		if (bytes == null) {
			throw new IllegalArgumentException("[bytes] must not be [null]");
		}
		this.value = ByteBuffer.allocateDirect(bytes.length);
		this.value.put(bytes);
		this.destroyed = new AtomicBoolean(false);
	}

	/**
	 * Erzeugt eine Instanz durch Kopie des übergebenen {@link OctetString}s.
	 *
	 * @param other
	 *            zu kopierender {@link OctetString}
	 */
	public OctetString(final OctetString other) {
		if (other == null) {
			throw new IllegalArgumentException("[other] must not be [null]");
		}

		final ByteBuffer otherValue = other.value;
		this.value = ByteBuffer.allocateDirect(otherValue.capacity());
		otherValue.rewind();
		this.value.put(otherValue);
		this.destroyed = new AtomicBoolean(false);
	}

	/**
	 * Erzeugt eine Instanz durch Kopie des übergebenen {@link ByteBuffer}s.
	 *
	 * @param buffer
	 *            zu kopierender {@link ByteBuffer}
	 */
	public OctetString(final ByteBuffer buffer) {
		if (buffer == null) {
			throw new IllegalArgumentException("[buffer] must not be [null]");
		}
		this.value = ByteBuffer.allocateDirect(buffer.capacity());
		buffer.rewind();
		this.value.put(buffer);
		this.destroyed = new AtomicBoolean(false);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((this.value == null) ? 0 : this.value.hashCode());
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		final OctetString other = (OctetString) obj;
		if (this.value == null) {
			if (other.value != null) {
				return false;
			}
		} else if (!this.value.equals(other.value)) {
			return false;
		}
		return true;
	}

	public void destroy() throws DestroyFailedException {
		this.value.rewind();
		final byte[] erasure = new byte[this.value.capacity()];
		Arrays.fill(erasure, (byte) 0);
		this.value.put(erasure);
		this.destroyed.set(true);
	}

	public byte[] toBytes() {
		final byte[] result = new byte[this.value.capacity()];
		this.value.rewind();
		this.value.get(result);
		return result;
	}

	/**
	 * Konvertiert den {@link OctetString} in einen {@link int}-Wert. Falls der
	 * {@link OctetString} einen höheren Wert repräsentiert, als als
	 * {@link int}-Wert dargestellt werden kann, werden nur die letzten 32 Bits
	 * verwendet.
	 *
	 *
	 * @return {@link int}-Wert
	 */
	public final int intValue(final int offset, final int length) {
		final BigInteger integer = this.toInteger(offset, length);
		final int result = integer.intValue();
		EraseUtil.clearBigInteger(integer);
		return result;
	}

	public boolean isDestroyed() {
		return this.destroyed.get();
	}

	/**
	 * Liefert die Anzahl der Oktette des {@link OctetString}s.
	 *
	 * @return Anzahl der Oktette
	 */
	public final int length() {
		return this.value.capacity();
	}

	/**
	 * Liefert das Oktett am angegebenen Index. Ein Index ist gültig von
	 * {@code 0} bis {@code length() - 1}. Das erste Oktett entspricht Index
	 * {@code 0}, das folgende Index {@code 1}, und so weiter.
	 *
	 * @param index
	 *            Index des gesuchten Oktetts
	 * @return gesuchtes Oktett
	 * @exception IndexOutOfBoundsException
	 *                falls der angegebene Index negativ oder nicht kleiner als
	 *                die Länge dieses {@link OctetString}s ist
	 */
	public final byte octetAt(final int index) {
		this.value.rewind();
		return this.value.get(index);
	}

	/**
	 * Liefert einen {@link OctetString} der ein Teil dieses
	 * {@link OctetString}s ist. Der Teil beginnt mit dem Oktett am übergebenen
	 * Index und endet mit dem Ende dieses {@link OctetString}s.
	 *
	 * @param beginIndex
	 *            Beginn-Index, inklusive
	 * @return Teil-{@link OctetString}
	 * @exception IndexOutOfBoundsException
	 *                falls {@code beginIndex} negativ oder größer als die Länge
	 *                dieses {@link OctetString}s ist
	 */
	public final OctetString substring(final int beginIndex) {
		if (beginIndex < 0) {
			throw new StringIndexOutOfBoundsException(beginIndex);
		}
		final int subLen = this.length() - beginIndex;
		if (subLen < 0) {
			throw new StringIndexOutOfBoundsException(subLen);
		}
		final ByteBuffer buffer = ByteBuffer.allocateDirect(subLen);
		this.value.position(beginIndex);
		buffer.put(this.value.slice());
		return new OctetString(buffer);
	}

	/**
	 * Converts an octet string to an integer. Based on BSI TR 03111 Section
	 * 3.1.2.
	 *
	 * @param offset
	 *            octet string
	 *
	 * @return positive integer
	 */
	private final BigInteger toInteger(final int offset, final int length) {
		BigInteger result = BigInteger.ZERO;
		final BigInteger base = BigInteger.valueOf(256);
		for (int i = offset; i < (offset + length); i++) {
			result = result.multiply(base);
			result = result.add(BigInteger.valueOf(this.octetAt(i) & 0xFF));
		}
		return result;
	}

	public static final void destroy(final OctetString octetString) {
		if (!octetString.isDestroyed()) {
			try {
				octetString.destroy();
			} catch (final DestroyFailedException e) {
				LOG.log(Level.WARNING, "Sicheres Löschen eines OctetStrings fehlgeschlagen", e);
			}
		}
	}

}