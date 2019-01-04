import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyPair;
import java.math.BigInteger;

public class Wallet {

    private ECPrivateKeyParameters privK;
    public  ECPublicKeyParameters pubK;

    public Wallet() {
        try {
            ECKeyPairGenerator g = new ECKeyPairGenerator();
            X9ECParameters secnamecurves = SECNamedCurves.getByName("secp256k1");
            ECDomainParameters ecParams = new ECDomainParameters(secnamecurves.getCurve(), secnamecurves.getG(), secnamecurves.getN(), secnamecurves.getH());
            ECKeyGenerationParameters keyGenParam = new ECKeyGenerationParameters(ecParams, new SecureRandom());
            g.init(keyGenParam);
            AsymmetricCipherKeyPair pair = g.generateKeyPair();
            pubK = (ECPublicKeyParameters) pair.getPublic();
            privK = (ECPrivateKeyParameters) pair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public BigInteger[] sign(String msg) {
        try {

            ECDSASigner sig = new ECDSASigner();
            byte[] data = Utils.sha1(msg);
            sig.init(true, privK);
            return sig.generateSignature(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public ECPublicKeyParameters getPublic(){
        return pubK;
    }

    @Override
    public String toString() {
        return Hex.toHexString(pubK.getQ().getEncoded(true));
    }

}
