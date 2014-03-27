package com.bitsofproof.supernode.misc;

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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Test;

import com.bitsofproof.supernode.api.Address;
import com.bitsofproof.supernode.api.Network;
import com.bitsofproof.supernode.common.ByteUtils;
import com.bitsofproof.supernode.common.ExtendedKey;
import com.bitsofproof.supernode.common.Key;
import com.bitsofproof.supernode.common.ValidationException;

public class BIP39Test
{
	@BeforeClass
	public static void init ()
	{
		Security.addProvider (new BouncyCastleProvider ());
	}

	private static final String TESTS = "BIP39.json";

	private JSONObject readObject (String resource) throws IOException, JSONException
	{
		InputStream input = this.getClass ().getResource ("/" + resource).openStream ();
		StringBuffer content = new StringBuffer ();
		byte[] buffer = new byte[1024];
		int len;
		while ( (len = input.read (buffer)) > 0 )
		{
			byte[] s = new byte[len];
			System.arraycopy (buffer, 0, s, 0, len);
			content.append (new String (buffer, "UTF-8"));
		}
		return new JSONObject (content.toString ());
	}

	@Test
	public void bip39TrezorTest () throws IOException, JSONException, ValidationException
	{
		JSONObject testData = readObject (TESTS);
		JSONArray english = testData.getJSONArray ("english");
		for ( int i = 0; i < testData.length (); ++i )
		{
			JSONArray test = english.getJSONArray (i);
			String m = BIP39.getMnemonic (ByteUtils.fromHex (test.getString (i)));
			assertTrue (m.equals (test.getString (i + 1)));
		}
	}

	@Test
	public void bip39EncodeDecodeTest () throws IOException, JSONException, ValidationException
	{
		JSONObject testData = readObject (TESTS);
		JSONArray english = testData.getJSONArray ("english");
		for ( int i = 0; i < testData.length (); ++i )
		{
			JSONArray test = english.getJSONArray (i);
			byte[] m = BIP39.decode (test.getString (1), "BOP");
			assertTrue (test.getString (1).equals (BIP39.encode (m, "BOP")));
		}
		SecureRandom random = new SecureRandom ();
		for ( int i = 0; i < 100; ++i )
		{
			byte[] secret = new byte[32];
			random.nextBytes (secret);
			String e = BIP39.encode (secret, "BOP");
			assertTrue (Arrays.equals (BIP39.decode (e, "BOP"), secret));
		}
	}

	@Test
	public void seedTest () throws IOException, JSONException, ValidationException
	{
		JSONObject testData = readObject (TESTS);
		JSONArray english = testData.getJSONArray ("english");
		for ( int i = 0; i < testData.length (); ++i )
		{
			JSONArray test = english.getJSONArray (i);
			String s = ByteUtils.toHex (BIP39.getSeed (test.getString (1), "TREZOR"));
			String target = test.getString (2);
			assertTrue (target.equals (s));
		}
	}

	@Test
	public void addressTest () throws ValidationException
	{
		// This is a random TREZOR backtest
		byte[] seed = BIP39.getSeed ("skull kite mother rebel rocket muffin luxury current alley teach write flower", "");
		ExtendedKey key = ExtendedKey.create (seed);
		// m/0/0'/0'/0/0
		Key k = key.getChild (0).getChild (0x80000000).getChild (0x80000000).getChild (0).getKey (0);
		Address a = k.getAddress ();
		a.setNetwork (Network.TEST);
		assertTrue ("moRW5Q9GYArPg3cwpBmdwQeNDcqiwhC6ga".equals (a.toString ()));
	}
}
