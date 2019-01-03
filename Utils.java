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

public class Utils {

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

    public static boolean verifiy(String str, PublicKey pubK, Signature sig, byte[] signatureBytes) {
        try {
            byte[] data = str.getBytes("UTF8");
            sig.initVerify(pubK);
            sig.update(data);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
