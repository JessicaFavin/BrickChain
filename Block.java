public class Block {

    public String previousBlock;
    public String transaction;
    public String signedTx;
    public String salt;
    public String hash;

    public Block(Block previousBlock, String transaction, boolean salted) {
        this.previousBlock = previousBlock.hash;
        this.transaction = transaction;
        this.signedTx = "";
        if(salted) {
            this.salt = Utils.findSalt(this.previousBlock+this.transaction);
        } else {
            this.salt = "";
        }
        this.hash = Utils.sha3(this.previousBlock+this.transaction+this.salt);
    }

    public Block(Block previousBlock, String transaction, String signedTx, boolean salted) {
        this.previousBlock = previousBlock.hash;
        this.transaction = transaction;
        this.signedTx = signedTx;
        if(salted) {
            this.salt = Utils.findSalt(this.previousBlock+this.transaction+this.signedTx);
        } else {
            this.salt = "";
        }
        this.hash = Utils.sha3(this.previousBlock+this.transaction+this.signedTx+this.salt);
    }

    public Block(String hash) {
        this.previousBlock = "";
        this.transaction = "";
        this.salt = "";
        this.hash = hash;
    }

    @Override
    public String toString() {
        return this.hash;
    }

}
