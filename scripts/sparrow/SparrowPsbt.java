import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;

import java.util.*;

/* Drives Sparrow 2.2.3's own wallet code (drongo, from the signed release) to
   create PSBTs through the same calls the Send tab makes:
   wallet.createWalletTransaction(...) then walletTransaction.createPSBT().
   Prints: name <TAB> base64, where base64 is what "Copy as Base64" returns. */
public class SparrowPsbt {
    static final String MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    static final String OTHER = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    static int fundingNonce = 1;

    static Wallet wallet(String mnemonic, ScriptType type, WalletModel model) throws Exception {
        Wallet w = new Wallet();
        w.setName("w");
        w.setPolicyType(PolicyType.SINGLE);
        w.setScriptType(type);
        DeterministicSeed seed = new DeterministicSeed(mnemonic, "", 0, DeterministicSeed.Type.BIP39);
        Keystore ks = Keystore.fromSeed(seed, type.getDefaultDerivation());
        ks.setWalletModel(model);
        w.getKeystores().add(ks);
        w.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE, type, w.getKeystores(), null));
        w.setStoredBlockHeight(200_000);
        w.getNode(KeyPurpose.RECEIVE).fillToIndex(20);
        w.getNode(KeyPurpose.CHANGE).fillToIndex(20);
        return w;
    }

    static WalletNode node(Wallet w, KeyPurpose p, int i) {
        for(WalletNode n : w.getNode(p).getChildren()) if(n.getIndex() == i) return n;
        throw new IllegalStateException("no node " + i);
    }

    /* A confirmed coin of `value` sats on receive address i. */
    static BlockTransactionHashIndex fund(Wallet w, int i, long value) {
        WalletNode n = node(w, KeyPurpose.RECEIVE, i);
        Transaction funding = new Transaction();
        byte[] prev = new byte[32];
        prev[0] = (byte)fundingNonce++;
        funding.addInput(Sha256Hash.wrap(prev), 0, new Script(new byte[0]));
        funding.addOutput(value, w.getAddress(n));
        Map<Sha256Hash, BlockTransaction> txs = new HashMap<>(w.getTransactions());
        txs.put(funding.getTxId(), new BlockTransaction(funding.getTxId(), 199_000, new Date(0), 0L, funding));
        w.updateTransactions(txs);
        BlockTransactionHashIndex utxo = new BlockTransactionHashIndex(funding.getTxId(), 199_000, new Date(0), 0L, 0, value);
        n.getTransactionOutputs().add(utxo);
        return utxo;
    }

    /* Coin control (PresetUtxoSelector), as when the user picks coins in the UTXOs tab. */
    static PSBT create(Wallet w, List<BlockTransactionHashIndex> coins, List<Payment> payments) throws Exception {
        WalletTransaction wt = w.createWalletTransaction(List.of(new PresetUtxoSelector(coins)), List.of(),
                payments, List.of(), Set.of(), 2.0, 1.0, null, 200_000, true, false);
        return wt.createPSBT();
    }

    static Address pay(Wallet other, int i) { return other.getAddress(node(other, KeyPurpose.RECEIVE, i)); }

    public static void main(String[] args) throws Exception {
        Network.set(Network.SIGNET);
        Wallet recipient = wallet(OTHER, ScriptType.P2WPKH, WalletModel.SEED);
        Wallet recipientTr = wallet(OTHER, ScriptType.P2TR, WalletModel.SEED);
        Map<String, String> out = new LinkedHashMap<>();

        /* Demo A: three coins incl. a small one, round payment. */
        Wallet a = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        List<BlockTransactionHashIndex> ca = List.of(fund(a, 0, 80_000), fund(a, 1, 70_000), fund(a, 2, 600));
        out.put("p2wpkh_demo_a", create(a, ca, List.of(new Payment(pay(recipient, 0), "pay", 100_000, false))).toBase64String());

        /* Demo B: same payment from one coin. */
        Wallet b = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        List<BlockTransactionHashIndex> cb = List.of(fund(b, 3, 200_000));
        PSBT pb = create(b, cb, List.of(new Payment(pay(recipient, 0), "pay", 100_000, false)));
        out.put("p2wpkh_demo_b", pb.toBase64String());
        out.put("p2wpkh_demo_b_file", Utils.bytesToHex(pb.serialize()));
        /* The PSBTv2 form of the same kind of transaction (drongo master defaults to v2;
           2.2.3's direct v2 constructor throws, so convert as Sparrow's combine does). */
        Wallet b2 = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        WalletTransaction wt2 = b2.createWalletTransaction(List.of(new PresetUtxoSelector(List.of(fund(b2, 3, 200_000)))), List.of(),
                List.of(new Payment(pay(recipient, 0), "pay", 100_000, false)), List.of(), Set.of(), 2.0, 1.0, null, 200_000, true, false);
        PSBT v2 = wt2.createPSBT();
        v2.convertVersion(2);
        out.put("p2wpkh_demo_b_psbt_v2", v2.toBase64String());

        /* Taproot wallet: two coins, non-round payment to a p2wpkh recipient. */
        Wallet t = wallet(MNEMONIC, ScriptType.P2TR, WalletModel.SEED);
        List<BlockTransactionHashIndex> ct = List.of(fund(t, 0, 80_000), fund(t, 1, 70_000));
        out.put("p2tr_two_coins", create(t, ct, List.of(new Payment(pay(recipient, 1), "pay", 123_457, false))).toBase64String());

        /* Taproot to taproot, one coin. */
        Wallet t2 = wallet(MNEMONIC, ScriptType.P2TR, WalletModel.SEED);
        out.put("p2tr_to_p2tr", create(t2, List.of(fund(t2, 4, 300_000)),
                List.of(new Payment(pay(recipientTr, 2), "pay", 150_000, false))).toBase64String());

        /* Hardware-wallet model that always includes the full previous tx. */
        Wallet hw = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.TREZOR_1);
        out.put("p2wpkh_trezor_non_witness_utxo", create(hw, List.of(fund(hw, 5, 250_000)),
                List.of(new Payment(pay(recipient, 3), "pay", 100_000, false))).toBase64String());

        /* Nested segwit (p2sh-p2wpkh). */
        Wallet sh = wallet(MNEMONIC, ScriptType.P2SH_P2WPKH, WalletModel.SEED);
        out.put("p2sh_p2wpkh", create(sh, List.of(fund(sh, 0, 250_000)),
                List.of(new Payment(pay(recipient, 4), "pay", 100_000, false))).toBase64String());

        /* Send to one of this wallet's own receive addresses. */
        Wallet s = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        out.put("p2wpkh_self_send", create(s, List.of(fund(s, 6, 250_000)),
                List.of(new Payment(pay(s, 10), "to self", 100_000, false))).toBase64String());

        /* Send max: no change output. */
        Wallet m = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        out.put("p2wpkh_send_max", create(m, List.of(fund(m, 7, 250_000)),
                List.of(new Payment(pay(recipient, 5), "pay", 240_000, true))).toBase64String());

        /* Batch: two payments plus change. */
        Wallet bt = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        out.put("p2wpkh_batch", create(bt, List.of(fund(bt, 8, 500_000)),
                List.of(new Payment(pay(recipient, 6), "a", 100_000, false),
                        new Payment(pay(recipient, 7), "b", 200_000, false))).toBase64String());

        /* Demo B after clicking Sign: Sparrow signs, then finalises (HeadersController.finalizePSBT). */
        Wallet sg = wallet(MNEMONIC, ScriptType.P2WPKH, WalletModel.SEED);
        PSBT ps = create(sg, List.of(fund(sg, 3, 200_000)), List.of(new Payment(pay(recipient, 0), "pay", 100_000, false)));
        sg.sign(ps);
        out.put("p2wpkh_signed_only", ps.toBase64String());
        sg.finalise(ps);
        out.put("p2wpkh_signed_finalized", ps.toBase64String());

        for(Map.Entry<String, String> e : out.entrySet()) System.out.println(e.getKey() + "\t" + e.getValue());
    }
}
