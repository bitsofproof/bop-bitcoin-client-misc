/*
 * Copyright 2014 bits of proof zrt.
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

import com.bitsofproof.supernode.api.Address;
import com.bitsofproof.supernode.common.ECPublicKey;
import com.bitsofproof.supernode.common.Hash;
import com.bitsofproof.supernode.common.ValidationException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.Arrays;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ArmoryWatchOnly
{
    private List<Address> receiverAddresses = new ArrayList<>();
    private Map<Long,Address> changeAddresses = new HashMap<>();
    private long lastChangeAddressIndex = 0;
    private byte [] pubkey = new byte [65];
    private byte [] chainCode = new byte [32];
    private static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");

    public ArmoryWatchOnly (String walletFile) throws FileNotFoundException, IOException, ValidationException
    {
        InputStream w = new FileInputStream(walletFile);
        w.read();
        byte [] prefix = new byte [6];
        w.read(prefix);

        if ( !new String (prefix).equals("WALLET") )
        {
            throw new ValidationException("Not a Wallet file");
        }

        byte [] dummy = new byte[319];
        w.read(dummy);
        byte [] highest = new byte [8];
        w.read(highest);
        lastChangeAddressIndex = highest[3];
        lastChangeAddressIndex <<= 8;
        lastChangeAddressIndex += highest[2];
        lastChangeAddressIndex <<= 8;
        lastChangeAddressIndex += highest[1];
        lastChangeAddressIndex <<= 8;
        lastChangeAddressIndex += highest[0]+2;
        byte [] dummy3 = new byte [512];
        w.read(dummy3);
        byte [] pubkeyhash = new byte [20];
        w.read(pubkeyhash);
        byte [] dummy2 = new byte [16];
        w.read(dummy2);
        w.read(chainCode);
        byte [] dummy4= new byte[76];
        w.read(dummy4);
        pubkey = new byte [65];
        w.read(pubkey);
        ECPublicKey k = new ECPublicKey (pubkey, false);
        if ( !Arrays.areEqual(k.getAddress().toByteArray(), pubkeyhash) )
        {
            throw new ValidationException("Could not parse");
        }
        byte [] dummy5 = new byte [28+1024];
        w.read(dummy5);
        int t;
        while ( (t = w.read ()) >= 0 )
        {
            if ( t == 0 )
            {
                byte [] h = new byte [20];
                w.read(h);
                receiverAddresses.add(new Address(Address.Type.COMMON, h));
                byte [] dummy6 = new byte [237];
                w.read(dummy6);
            }
            else if ( t == 1 )
            {
                byte [] h = new byte [20];
                w.read(h);
                int l = w.read() + w.read() << 8;
                byte [] dummy7 = new byte [l];
                w.read(dummy7);
            }
            else if ( t == 2 )
            {
                byte [] h = new byte [32];
                w.read(h);
                int l = w.read() + w.read() << 8;
                byte [] dummy7 = new byte [l];
                w.read(dummy7);
            }
            else if ( t == 3 )
            {
                int l = w.read() + w.read() << 8;
                byte [] dummy7 = new byte [l];
                w.read(dummy7);
            }
            else
            {
                throw new ValidationException("Unknown record in wallet");
            }
        }
    }

    public Address getChangeAddress (long n)
    {
        if ( !changeAddresses.containsKey(n) )
        {
            for ( long i = changeAddresses.size(); i <= n; ++i )
            {
                ECPublicKey k = new ECPublicKey(pubkey, false);
                Address a = k.getAddress();
                changeAddresses.put(i, a);
                byte[] m = Hash.hash(pubkey);
                for (int j = 0; j < 32; ++j)
                {
                    m[j] ^= chainCode[j];
                }
                pubkey = curve.getCurve().decodePoint (pubkey).multiply (new BigInteger(1, m)).getEncoded (false);
            }
            lastChangeAddressIndex = Math.max (changeAddresses.size(), lastChangeAddressIndex);
        }
        return changeAddresses.get(n);
    }

    public Address getNextChangeAddress ()
    {
        return getChangeAddress (lastChangeAddressIndex++);
    }

    public long getLastChangeAddressIndex()
    {
        return lastChangeAddressIndex;
    }

    public List<Address> getReceiverAddresses ()
    {
        return receiverAddresses;
    }
}
