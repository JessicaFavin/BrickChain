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
        System.out.println("''      -> "+Utils.sha3(""));
        System.out.println("'abc'   -> "+Utils.sha3("abc"));
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** Hash Chain ***");
        System.out.println("Init the Hash Chain: h0 = "+h0);
        h1 = Utils.sha3(h0+"a");
        System.out.println("Add a New Block 'a': h1 = "+h1);
        h2 = Utils.sha3(h1+"b");
        System.out.println("Add a New Block 'b': h2 = "+h2);
        //------------------------------------------------------------------------------------------------------
        System.out.println("\n*** Hash Chain with Proof of Work ***");
        System.out.println("Init the Hash Chain: h0 = "+h0);
        //r1 = "5f4ed62e156a501e";
        r1 = Utils.findSalt(h0+"a");
        h1 = Utils.sha3(h0+"a"+r1);
        System.out.println("Add a New Block 'a': h1 = Utils.sha3("+h0
        +"\n                               || a || "+r1
        +")\n                        = "+h1);

        r2 = Utils.findSalt(h1+"b");
        h2 = Utils.sha3(h1+"b"+r2);
        System.out.println("Add a New Block 'b': h2 = Utils.sha3("+h1
        +"\n                               || b || "+r2
        +")\n                        = "+h2);
        //------------------------------------------------------------------------------------------------------
        PublicKey vk1, vk2, vk3;
        PrivateKey sk1, sk2, sk3;
        try{

            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
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
            System.out.println("Encoding = "+vk1.getFormat());
            System.out.println("Wallet 1 = vk1 = "+Hex.toHexString(vk1.getEncoded()));
            System.out.println("Private 1 = sk1 = "+Hex.toHexString(sk1.getEncoded()));
            System.out.println("Wallet 2 = vk2 = "+Hex.toHexString(vk2.getEncoded()));
            System.out.println("Private 2 = sk2 = "+Hex.toHexString(sk2.getEncoded()));
            System.out.println("Wallet 3 = vk3 = "+Hex.toHexString(vk3.getEncoded()));
            System.out.println("Private 3 = sk3 = "+Hex.toHexString(sk3.getEncoded()));


            //------------------------------------------------------------------------------------------------------
            System.out.println("\n*** BlockChain of Transactions ***");
            System.out.println("Init the Hash Chain: h0 = "+h0);
            r1 = Utils.findSalt(h0+Hex.toHexString(vk1.getEncoded())+" receives 10 Euros");
            h1 = Utils.sha3(h0+Hex.toHexString(vk1.getEncoded())+" receives 10 Euros"+r1);

            System.out.println("Add a New Block '"+Hex.toHexString(vk1.getEncoded())+" \n\t\treceives 10 Euros'");
            System.out.println("   -> h1 = SHA3("+h0+" ");
            System.out.println("                || "+Hex.toHexString(vk1.getEncoded())+" \n\t\treceives 10 Euros");
            System.out.println("                || "+r1+")");
            System.out.println("              = "+h1);
            //-------------------------------------------------------------------------------------------------------
            byte[] data = "test".getBytes("UTF8");
            Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
            sig.initSign(sk1);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            System.out.println("--------------------------------------------");
            System.out.println(signatureBytes.length);
            System.out.println(Hex.toHexString(signatureBytes));
            sig.initVerify(vk1);
            sig.update(data);
            System.out.println(sig.verify(signatureBytes));
            System.out.println("--------------------------------------------");
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

}
