import java.security.MessageDigest;

import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.util.encoders.Hex;

public class BrickChain {
    public static void main(String[] args) {
        System.out.println(sha3(""));
    }

    public void testSha3(String input) {
        // = "Hello world !";
        DigestSHA3 digestSHA3 = new Digest256();
        byte[] digest = digestSHA3.digest(input.getBytes());
        System.out.println("SHA3-256 = " + Hex.toHexString(digest));
    }
}
