import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.util.encoders.Hex;
import java.security.MessageDigest;

public class BrickChain {
    public static void main(String[] args) {
        String toot = "value";
        System.out.println("*** SHA3 Vector Tests ***");
        System.out.println("''      -> "+sha3(""));
        System.out.println("'abc'   -> "+sha3("abc"));

        System.out.println("\n*** Hash Chain ***");
        System.out.println("Init the Hash Chain: h0 = "+toot);
        System.out.println("Add a New Block 'a': h1 = "+toot);
        System.out.println("Add a New Block 'b': h2 = "+toot);

        System.out.println("\n*** Hash Chain with Proof of Work ***");
        System.out.println("Init the Hash Chain: h0 = "+toot);
        System.out.println("Add a New Block 'a': h1 = SHA3("+toot
                        +"\n                               || a || "+toot
                        +")\n                       = "+toot);
        System.out.println("Add a New Block 'b': h2 = SHA3("+toot
                        +"\n                               || b || "+toot
                        +")\n                       = "+toot);

        System.out.println("\n*** Key Generation ***");
        System.out.println("Wallet 1 = vk1 = "+toot);
        System.out.println("Wallet 2 = vk2 = "+toot);
        System.out.println("Wallet 3 = vk3 = "+toot);
        //--> ECDSA
        System.out.println("\n*** BlockChain of Transactions ***");
        System.out.println("Init the Hash Chain: h0 = "+toot);
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

    public static String sha3(String input) {
        DigestSHA3 digestSHA3 = new Digest256();
        byte[] digest = digestSHA3.digest(input.getBytes());
         return Hex.toHexString(digest);
    }
}
