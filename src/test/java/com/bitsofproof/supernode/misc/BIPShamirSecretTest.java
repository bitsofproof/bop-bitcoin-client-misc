package com.bitsofproof.supernode.misc;

import org.junit.Test;

import com.bitsofproof.supernode.common.ECKeyPair;
import com.bitsofproof.supernode.common.ValidationException;

public class BIPShamirSecretTest
{
	@Test
	public void testVectors () throws ValidationException
	{
		ECKeyPair kp = ECKeyPair.parseWIF ("L4Shamir4KSghoE4uGhHJMFiG2ZrXRXydMgFvCUaCLgXQ88YKBMz");
		String[] shares = BIPShamirSecret.cut (kp, 6, 3);
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
		String[] shares = BIPShamirSecret.cut (kp, 6, 3);
		ECKeyPair kp2 = BIPShamirSecret.reconstruct (shares);
		System.out.println (ECKeyPair.serializeWIF (kp2));

		for ( String s : shares )
		{
			System.out.println (s);
		}

	}
}
