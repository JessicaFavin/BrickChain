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

public class Wallet {

    private PrivateKey privK;
    public  PublicKey pubK;
    private Signature sig;
    private byte[] signatureBytes;

    public Wallet() {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            pubK = pair.getPublic();
            privK = pair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sign(String str) {
        try {
            byte[] data = str.getBytes("UTF8");
            sig = Signature.getInstance("SHA256withECDSA", "BC");
            sig.initSign(privK);
            sig.update(data);
            signatureBytes = sig.sign();
            //return the signatureByte or sig
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
