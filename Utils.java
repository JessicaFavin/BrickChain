import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.math.BigInteger;

public final class Utils {

    public static byte[] sha1(String input) {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-1", "BC");
            hash.update(input.getBytes());
            return hash.digest();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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

    public static boolean verify(ECPublicKeyParameters pubK, String msg, BigInteger r, BigInteger s) {
        try {
            ECDSASigner sig = new ECDSASigner();
            byte[] data = Utils.sha1(msg);
            sig.init(false, pubK);
            return sig.verifySignature(data, r, s);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
