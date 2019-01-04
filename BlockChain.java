import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.PublicKey;
import java.security.Security;
import java.util.LinkedList;
import java.math.BigInteger;
import java.util.Arrays;

public class BlockChain {
    LinkedList<Block> chain;

    public BlockChain() {
        chain = new LinkedList<Block>();
    }

    public void add(Block nextBlock) {
        this.chain.add(nextBlock);
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        BrickChain blockChain = new BrickChain();

        Block block0, block1, block2, block3;
        Wallet wallet1, wallet2, wallet3;
        BigInteger[] signedTx;
        boolean valid;
        String tx, tmp;

        block0 = new Block("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        blockChain.add(block0);

        //------------------------------------------------------------------------------------------------------

        System.out.println("\n\n*** SHA3 Vector Tests ***\n");
        System.out.println("''      -> "+Utils.sha3(""));
        System.out.println("'abc'   -> "+Utils.sha3("abc"));

        //------------------------------------------------------------------------------------------------------

        System.out.println("\n\n*** Hash Chain ***\n");
        System.out.println("Init the Hash Chain: h0 = "+block0);

        block1 = new Block(block0, "a", false);
        blockChain.add(block1);
        System.out.println("Add a New Block 'a': h1 = "+block1);

        block2 = new Block(block1, "b", false);
        blockChain.add(block2);
        System.out.println("Add a New Block 'b': h2 = "+block2);

        //------------------------------------------------------------------------------------------------------

        System.out.println("\n\n*** Hash Chain with Proof of Work ***\n");
        blockChain = new BrickChain();
        System.out.println("Init the Hash Chain: h0 = "+block0);
        blockChain.add(block0);

        block1 = new Block(block0, "a", true);
        blockChain.add(block1);
        System.out.println("\nAdd a New Block 'a': h1 = SHA3("+block0
        +"\n                               || a || "+block1.salt
        +")\n                        = "+block1);

        block2 = new Block(block1, "b", true);
        blockChain.add(block2);
        System.out.println("\nAdd a New Block 'b': h2 = SHA3("+block1
        +"\n                               || b || "+block2.salt
        +")\n                        = "+block2);

        //------------------------------------------------------------------------------------------------------

        System.out.println("\n\n*** Key Generation ***\n");

        wallet1 = new Wallet();
        wallet2 = new Wallet();
        wallet3 = new Wallet();

        System.out.println("Wallet 1 = vk1 = " + wallet1);
        System.out.println("Wallet 2 = vk2 = " + wallet2);
        System.out.println("Wallet 3 = vk3 = " + wallet3);

        //------------------------------------------------------------------------------------------------------

        System.out.println("\n\n*** BlockChain of Transactions ***\n");

        blockChain = new BrickChain();
        System.out.println("Init the Hash Chain: h0 = "+block0);
        blockChain.add(block0);

        tx = wallet1+" receives 10 Euros";
        block1 = new Block(block0,tx,true);
        blockChain.add(block1);
        System.out.println("\nAdd a New Block '"+tx+"'");
        System.out.println("   -> h1 = SHA3("+block0+" ");
        System.out.println("                || "+tx);
        System.out.println("                || "+block1.salt+")");
        System.out.println("              = "+block1);

        try {

            tx = wallet1.toString()+" gives 5 Euros to "+wallet2.toString();
            signedTx = wallet1.sign(tx);
            tmp = signedTx[0].toString(16)+signedTx[0].toString(16);
            block2 = new Block(block1,tx, tmp, true);
            blockChain.add(block2);
            System.out.println("\nAdd a New Block '"+tx+"'");
            System.out.println("   -> h2 = SHA3("+block1+" ");
            System.out.println("                || "+tx);
            System.out.println("                || "+block2.signedTx+")");
            System.out.println("                || "+block2.salt+")");
            System.out.println("              = "+block2);
            valid = Utils.verify(wallet1.getPublic(), tx, signedTx[0], signedTx[1]);
            System.out.println("Validity of Signature: "+valid);

            tx = wallet1.toString()+" gives 5 Euros to "+wallet3.toString();
            signedTx = wallet1.sign(tx);
            tmp = signedTx[0].toString(16)+signedTx[0].toString(16);
            block3 = new Block(block2,tx, tmp, true);
            blockChain.add(block3);
            System.out.println("\nAdd a New Block '"+tx+"'");
            System.out.println("   -> h2 = SHA3("+block2+" ");
            System.out.println("                || "+tx);
            System.out.println("                || "+block3.signedTx+")");
            System.out.println("                || "+block3.salt+")");
            System.out.println("              = "+block3);
            valid = Utils.verify(wallet1.getPublic(), tx, signedTx[0], signedTx[1]);
            System.out.println("Validity of Signature: "+valid);

        } catch (Exception e) {
            e.printStackTrace();

        }

    }

}
