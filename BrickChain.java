import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.util.encoders.Hex;
import java.security.MessageDigest;

public class BrickChain {
    public static void main(String[] args) {
        System.out.println(sha3(""));
    }

    public static String sha3(String input) {
        DigestSHA3 digestSHA3 = new Digest256();
        byte[] digest = digestSHA3.digest(input.getBytes());
         return Hex.toHexString(digest);
    }
}
