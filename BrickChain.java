import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.util.encoders.Hex;
import java.security.MessageDigest;

public class BrickChain {
    public static void main(String[] args) {
        String h0, h1, h2, r1, r2, vk1, vk2, vk3;
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
        r1 = findSalt(h0, "a");
        h1 = sha3(h0+"a"+r1);
        System.out.println("Add a New Block 'a': h1 = SHA3("+h0
                        +"\n                               || a || "+r1
                        +")\n                        = "+h1);

        r2 = findSalt(h1, "b");
        h2 = sha3(h1+"b"+r2);
        System.out.println("Add a New Block 'b': h2 = SHA3("+h1
                        +"\n                               || b || "+r2
                        +")\n                        = "+h2);
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** Key Generation ***");
        System.out.println("Wallet 1 = vk1 = "+toot);
        System.out.println("Wallet 2 = vk2 = "+toot);
        System.out.println("Wallet 3 = vk3 = "+toot);
        //--> ECDSA
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** BlockChain of Transactions ***");
        System.out.println("Init the Hash Chain: h0 = "+h0);
        System.out.println("Add a New Block '"+toot+" receives 10 Euros'");
        System.out.println("   -> h1 = SHA3("+toot+" ");
        System.out.println("                || "+toot+" receives 10 Euros");
        System.out.println("                || "+toot+")");
        System.out.println("              = "+toot);
        System.out.println("Add a New Block '"+toot);
        System.out.println("                     gives 5 Euros to "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot+"'");
        System.out.println("   -> h2 = SHA3("+toot);
        System.out.println("                || "+toot);
        System.out.println("                     gives 5 Euros to "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot+")");
        System.out.println("              = "+toot);
        System.out.println("Validity of Signature: "+toot);
        System.out.println("Add a New Block '"+toot);
        System.out.println("                     gives 5 Euros to "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot+"'");
        System.out.println("   -> h3 = SHA3("+toot);
        System.out.println("                || "+toot);
        System.out.println("                     gives 5 Euros to "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot);
        System.out.println("                || "+toot+")");
        System.out.println("              = "+toot);
        System.out.println("Validity of Signature: "+toot);
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

    public static String findSalt(String h0, String value) {
        Long r = 0L;
        String h1;
        do {
            h1 = sha3(h0+value+Long.toHexString(r));
            r++;

        } while(!h1.endsWith("0000") && !Long.toHexString(r).equals("ffffffffffffffff"));

        return Long.toHexString(--r);
    }
}
