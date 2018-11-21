import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Hex;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.Security;
import java.security.KeyPair;
public class BrickChain {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        String h0, h1, h2, r1, r2;
        String toot = "value";
        h0 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        //------------------------------------------------------------------------------------------------------
        System.out.println("*** SHA3 Vector Tests ***");
        System.out.println("''      -> "+sha3(""));
        System.out.println("'abc'   -> "+sha3("abc"));
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** Hash Chain ***");
        System.out.println("Init the Hash Chain: h0 = "+h0);
        h1 = sha3(h0+"a");
        System.out.println("Add a New Block 'a': h1 = "+h1);
        h2 = sha3(h1+"b");
        System.out.println("Add a New Block 'b': h2 = "+h2);
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** Hash Chain with Proof of Work ***");
        System.out.println("Init the Hash Chain: h0 = "+h0);
        //r1 = "5f4ed62e156a501e";
        r1 = findSalt(h0+"a");
        h1 = sha3(h0+"a"+r1);
        System.out.println("Add a New Block 'a': h1 = SHA3("+h0
        +"\n                               || a || "+r1
        +")\n                        = "+h1);

        r2 = findSalt(h1+"b");
        h2 = sha3(h1+"b"+r2);
        System.out.println("Add a New Block 'b': h2 = SHA3("+h1
        +"\n                               || b || "+r2
        +")\n                        = "+h2);
        //------------------------------------------------------------------------------------------------------
        PublicKey vk1, vk2, vk3;
        PrivateKey sk1, sk2, sk3;
        try{

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            //Hex.toHexString(vk1.getEncoded())
            vk1 = pair.getPublic();
            sk1 = pair.getPrivate();
            g.initialize(ecSpec, new SecureRandom());
            pair = g.generateKeyPair();
            vk2 = pair.getPublic();
            sk2 = pair.getPrivate();
            g.initialize(ecSpec, new SecureRandom());
            pair = g.generateKeyPair();
            vk3 = pair.getPublic();
            sk3 = pair.getPrivate();
            System.out.println("\n*** Key Generation ***");
            System.out.println("Wallet 1 = vk1 = "+Hex.toHexString(vk1.getEncoded()));
            System.out.println("Wallet 2 = vk2 = "+Hex.toHexString(vk2.getEncoded()));
            System.out.println("Wallet 3 = vk3 = "+Hex.toHexString(vk3.getEncoded()));


            //------------------------------------------------------------------------------------------------------
            System.out.println("\n*** BlockChain of Transactions ***");
            System.out.println("Init the Hash Chain: h0 = "+h0);
            r1 = findSalt(h0+Hex.toHexString(vk1.getEncoded())+" receives 10 Euros");
            h1 = sha3(h0+Hex.toHexString(vk1.getEncoded())+" receives 10 Euros"+r1);

            System.out.println("Add a New Block '"+Hex.toHexString(vk1.getEncoded())+" \n\t\treceives 10 Euros'");
            System.out.println("   -> h1 = SHA3("+h0+" ");
            System.out.println("                || "+Hex.toHexString(vk1.getEncoded())+" \n\t\treceives 10 Euros");
            System.out.println("                || "+r1+")");
            System.out.println("              = "+h1);
            //-------------------------------------------------------------------------------------------------------
            byte[] data = "test".getBytes("UTF8");
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(sk1);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            sig.initVerify(vk1);
            sig.update(data);
            //System.out.println(sig.verify(signatureBytes));
            //--> true

            System.out.println("Add a New Block '"+Hex.toHexString(vk1.getEncoded()));
            System.out.println("                     gives 5 Euros to "+Hex.toHexString(vk2.getEncoded()));
            System.out.println("                || "+toot);
            System.out.println("                || "+toot+"'");
            System.out.println("   -> h2 = SHA3("+h1);
            System.out.println("                || "+Hex.toHexString(vk1.getEncoded()));
            System.out.println("                     gives 5 Euros to \n\t\t"+Hex.toHexString(vk2.getEncoded()));
            System.out.println("                || "+toot);
            System.out.println("                || "+toot);
            System.out.println("                || "+toot+")");
            System.out.println("              = "+toot);
            System.out.println("Validity of Signature: "+toot);
            System.out.println("Add a New Block '"+Hex.toHexString(vk2.getEncoded()));
            System.out.println("                     gives 5 Euros to "+Hex.toHexString(vk3.getEncoded()));
            System.out.println("                || "+toot);
            System.out.println("                || "+toot+"'");
            System.out.println("   -> h3 = SHA3("+toot);
            System.out.println("                || "+Hex.toHexString(vk2.getEncoded()));
            System.out.println("                     gives 5 Euros to "+Hex.toHexString(vk3.getEncoded()));
            System.out.println("                || "+toot);
            System.out.println("                || "+toot);
            System.out.println("                || "+toot+")");
            System.out.println("              = "+toot);
            System.out.println("Validity of Signature: "+toot);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
    * https://stackoverflow.com/questions/11208479/how-do-i-initialize-a-byte-array-in-java#11208685
    */
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
            + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static String sha3(String input) {
        DigestSHA3 digestSHA3 = new Digest256();
        byte[] digest = digestSHA3.digest(input.getBytes());
        return Hex.toHexString(digest);
    }

    public static String findSalt(String h0) {
        Long r = 0L;
        String h1;
        do {
            h1 = sha3(h0+Long.toHexString(r));
            r++;

        } while(!h1.endsWith("0000") && !Long.toHexString(r).equals("ffffffffffffffff"));

        return Long.toHexString(--r);
    }
}
