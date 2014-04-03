/*
 * Copyright 2013 bits of proof zrt.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.bitsofproof.supernode.misc;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.util.Arrays;

import com.bitsofproof.supernode.common.ByteUtils;
import com.bitsofproof.supernode.common.ECKeyPair;
import com.bitsofproof.supernode.common.ValidationException;

// WORK IN PROGRESS!

public class BIPShamirSecret
{
	private static final BigInteger prime16 = BigInteger.ONE.shiftLeft (16).subtract (BigInteger.valueOf (15));
	private static final BIPShamirSecret ss128 = new BIPShamirSecret (16, BigInteger.ONE.shiftLeft (128).subtract (BigInteger.valueOf (159)));
	private static final BIPShamirSecret ss192 = new BIPShamirSecret (24, BigInteger.ONE.shiftLeft (192).subtract (BigInteger.valueOf (237)));
	private static final BIPShamirSecret ss256 = new BIPShamirSecret (32, BigInteger.ONE.shiftLeft (256).subtract (BigInteger.valueOf (189)));
	private static final BIPShamirSecret ss384 = new BIPShamirSecret (48, BigInteger.ONE.shiftLeft (384).subtract (BigInteger.valueOf (317)));
	private static final BIPShamirSecret ss512 = new BIPShamirSecret (64, BigInteger.ONE.shiftLeft (512).subtract (BigInteger.valueOf (569)));

	private BigInteger secretModulo;
	private int secretLength;

	public BIPShamirSecret (int l, BigInteger m)
	{
		this.secretLength = l;
		this.secretModulo = m;
	}

	public static class SecretShare
	{
		public int needed;
		public int shareNumber;
		public BigInteger share;
		public byte[] fingerprint;
	}

	private static final byte[] legacy = { (byte) 0x1a, (byte) 0x46 };
	private static final byte[] legacyShort = { (byte) 0x26, (byte) 0xf4 };
	private static final byte[] compressed = { (byte) 0x1a, (byte) 0x47 };
	private static final byte[] compressedShort = { (byte) 0x26, (byte) 0xf6 };
	private static final byte[] bip32seed128 = { (byte) 0x0e, (byte) 0x53 };
	private static final byte[] bip32seed128Short = { (byte) 0x15, (byte) 0x3d };
	private static final byte[] bip32seed256 = { (byte) 0x1a, (byte) 0x49 };
	private static final byte[] bip32seed256Short = { (byte) 0x26, (byte) 0xf8 };
	private static final byte[] bip32seed512 = { (byte) 0x58, (byte) 0x7e };
	private static final byte[] bip32seed512Short = { (byte) 0x83, (byte) 0xa33 };

	public static String getShare (ECKeyPair key, int share, int needed, boolean verbose) throws ValidationException
	{
		SecretShare ss = ss256.getShare (key.getPrivate (), share, needed);
		return ss256.serialize (key.isCompressed () ? verbose ? compressed : compressedShort :
				verbose ? legacy : legacyShort, ss, verbose);
	}

	private static byte[] toArray (BigInteger n, int len)
	{
		byte[] p = n.toByteArray ();

		if ( p.length != len )
		{
			byte[] tmp = new byte[len];
			System.arraycopy (p, Math.max (0, p.length - len), tmp, Math.max (0, len - p.length), Math.min (len, p.length));
			return tmp;
		}
		return p;
	}

	private String serialize (byte[] secretType, SecretShare s, boolean verbose)
	{
		byte[] raw;
		if ( verbose )
		{
			raw = new byte[6 + secretLength];
		}
		else
		{
			raw = new byte[3 + secretLength];
		}
		System.arraycopy (secretType, 0, raw, 0, 2);
		if ( verbose )
		{
			System.arraycopy (s.fingerprint, 0, raw, 2, 2);
			raw[4] = (byte) (s.needed & 0xff - 2);
			raw[5] = (byte) s.shareNumber;
		}
		else
		{
			raw[2] = (byte) s.shareNumber;
		}
		System.arraycopy (toArray (s.share, 32), 0, raw, verbose ? 6 : 3, secretLength);
		return ByteUtils.toBase58WithChecksum (raw);
	}

	public static ECKeyPair reconstruct (String[] shares) throws ValidationException
	{
		SecretShare ss[] = new SecretShare[shares.length];

		boolean comp = true;
		for ( int i = 0; i < shares.length; ++i )
		{
			byte[] raw = ByteUtils.fromBase58WithChecksum (shares[i]);
			byte[] prefix = Arrays.copyOfRange (raw, 0, 2);
			boolean verbose = Arrays.areEqual (prefix, compressed) || !Arrays.areEqual (prefix, legacy);
			if ( !verbose && !Arrays.areEqual (prefix, compressedShort) && !Arrays.areEqual (prefix, legacyShort) )
			{
				throw new ValidationException ("Not a key share");
			}
			ss[i] = new SecretShare ();
			ss[i].shareNumber = raw[2] & 0xff;
			ss[i].share = new BigInteger (1, Arrays.copyOfRange (raw, verbose ? 6 : 3, 40));
			comp = raw[1] == compressed[1];
		}
		return new ECKeyPair (ss256.reconstruct (ss), comp);
	}

	private static byte[] hash (byte[] d, BigInteger mod, int length) throws ValidationException
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance ("SHA-512");
		}
		catch ( NoSuchAlgorithmException e )
		{
			throw new ValidationException (e);
		}
		return toArray (new BigInteger (1, digest.digest (d)).mod (mod), length);
	}

	private byte[] hash (byte[] d) throws ValidationException
	{
		return hash (d, secretModulo, secretLength);
	}

	public SecretShare getShare (byte[] secret, int share, int needed) throws ValidationException
	{
		if ( secret.length != secretLength )
		{
			throw new ValidationException ("Secret must be " + secretLength + " bytes");
		}
		if ( new BigInteger (1, secret).compareTo (secretModulo) >= 0 )
		{
			throw new ValidationException ("Secret is too big");
		}
		BigInteger[] a = new BigInteger[needed];
		byte[] r = toArray (new BigInteger (1, secret), secretLength);
		for ( int i = 0; i < a.length; ++i )
		{
			a[i] = new BigInteger (1, r);
			r = hash (r);
		}

		int x = share + 1;
		BigInteger y = a[0];
		for ( int i = 1; i < needed; ++i )
		{
			y = y.add (BigInteger.valueOf (x).pow (i).multiply (a[i]));
		}
		SecretShare ss = new SecretShare ();
		ss.shareNumber = (byte) share;
		ss.share = y.mod (secretModulo);
		ss.needed = needed;
		ss.fingerprint = hash (secret, prime16, 2);
		return ss;
	}

	public BigInteger reconstruct (SecretShare[] shares) throws ValidationException
	{
		for ( int i = 0; i < shares.length - 1; ++i )
		{
			for ( int j = 0; j < shares.length; ++j )
			{
				if ( i != j && shares[i].shareNumber == shares[j].shareNumber )
				{
					throw new ValidationException ("Shares are not unique");
				}
			}
		}
		BigInteger[] y = new BigInteger[shares.length];
		for ( int i = 0; i < shares.length; ++i )
		{
			y[i] = shares[i].share;
		}
		int d, i;
		for ( d = 1; d < shares.length; d++ )
		{
			for ( i = 0; i < shares.length - d; i++ )
			{
				int j = i + d;
				BigInteger xi = BigInteger.valueOf (shares[i].shareNumber + 1);
				BigInteger xj = BigInteger.valueOf (shares[j].shareNumber + 1);

				y[i] = xj.multiply (y[i]).subtract (xi.multiply (y[i + 1])).multiply (xj.subtract (xi).modInverse (secretModulo)).mod (secretModulo);
			}
		}
		return y[0];
	}
}
