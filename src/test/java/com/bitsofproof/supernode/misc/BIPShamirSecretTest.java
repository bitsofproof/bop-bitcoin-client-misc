package com.bitsofproof.supernode.misc;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import com.bitsofproof.supernode.common.ECKeyPair;
import com.bitsofproof.supernode.common.ValidationException;

public class BIPShamirSecretTest
{
	private static final String TESTS = "BIPShamirSecret.json";

	private JSONArray readArray (String resource) throws IOException, JSONException
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
		return new JSONArray (content.toString ());
	}

	// @Test
	public void testJSON () throws ValidationException, IOException, JSONException
	{
		JSONArray tests = readArray (TESTS);
		for ( int i = 0; i < tests.length (); ++i )
		{
			JSONObject test = tests.getJSONObject (i);
			if ( test.getString ("type").equals ("WIF") )
			{
				ECKeyPair key = ECKeyPair.parseWIF (test.getString ("key"));
				int m = test.getInt ("M");
				JSONArray shares = test.getJSONArray ("shares");
				for ( int j = 0; j < shares.length (); ++j )
				{
					if ( !shares.getString (j).equals (BIPShamirSecret.getShare (key, j, m)) )
					{
						System.out.println (" ** " + shares.getString (j));
						System.out.println (" ** " + BIPShamirSecret.getShare (key, j, m));
					}
					assertTrue (shares.getString (j).equals (BIPShamirSecret.getShare (key, j, m)));
				}
			}
		}
	}

	@Test
	public void testVectors () throws ValidationException
	{
		ECKeyPair kp = ECKeyPair.parseWIF ("L4Shamir4KSghoE4uGhHJMFiG2ZrXRXydMgFvCUaCLgXQ88YKBMz");
		String[] shares = new String[6];
		for ( int i = 0; i < 6; ++i )
		{
			shares[i] = BIPShamirSecret.getShare (kp, i, 3);
		}
		ECKeyPair kp2 = BIPShamirSecret.reconstruct (shares);
		System.out.println (ECKeyPair.serializeWIF (kp2));

		for ( String s : shares )
		{
			System.out.println (s);
		}

	}

	@Test
	public void testVectors2 () throws ValidationException
	{
		ECKeyPair kp = ECKeyPair.parseWIF ("5KShamir9pqYHfa63F2r9iA44sK4iDdo2gtyAXHCSRwuCLdqgCv");
		String[] shares = new String[6];
		for ( int i = 0; i < 6; ++i )
		{
			shares[i] = BIPShamirSecret.getShare (kp, i, 4);
		}
		ECKeyPair kp2 = BIPShamirSecret.reconstruct (shares);
		System.out.println (ECKeyPair.serializeWIF (kp2));

		for ( String s : shares )
		{
			System.out.println (s);
		}

	}
}
