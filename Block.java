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

public class Block {
    String previousBlock;
    String transaction;
    String salt;
    String hash;

    public Block(String previousBlock, String transaction) {
        this.previousBlock = previousBlock;
        this.transaction = transaction;
        this.salt = Utils.findSalt(this.previousBlock+this.transaction);
        this.hash = Utils.sha3(this.previousBlock+this.transaction+this.salt);
    }

    @Override
    public String toString() {
        return this.hash;
    }
}
