package ubi;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ubi.MerkleTree.MerkleProofStep;
import utils.DigestUtils;

public class Test {

    // Main : executa alinea d (prova), e (validação) e f (benchmark)
    public static void main(String[] args) throws Exception {
        String algo = (args.length >= 1 && args[0] != null && !args[0].trim().isEmpty()) ? args[0] : "SHA-256";
        int n = parseIntOr(args, 1, 10);          // 2º arg: expoente
        int idx = parseIntOr(args, 2, 0);         // 3º arg: índice da tx 
        int iters = parseIntOr(args, 3, 20_000);  // 4º arg: iterações

        DigestUtils digestUtils;
        try { digestUtils = new DigestUtils(algo); System.out.println("Algoritmo de hash: " + algo); }
        catch (Exception e) { System.err.println("Algoritmo inválido: " + algo + " — a usar SHA-256."); digestUtils = new DigestUtils("SHA-256"); }

        int count = 1 << n;
        List<String> txList = generateRandomDistinctTx(count, 16);
        System.out.println("Geradas " + count + " transacções aleatórias (2^" + n + ").");

        MerkleTree mTree = new MerkleTree(txList, digestUtils);
        if (n <= 5) mTree.printTreePretty(); // imprime só para árvores pequenas

        if (idx < 0 || idx >= txList.size()) idx = 0;
        String targetTx = txList.get(idx);
        List<MerkleProofStep> proof = mTree.getProofForTx(targetTx);
        String root = mTree.getRootHash();

        System.out.println("\nRoot: " + root);
        System.out.println("Tx alvo (idx " + idx + "): " + targetTx);
        System.out.print("Prova (tamanho " + proof.size() + "): [ ");
        for (int i = 0; i < proof.size(); i++) { System.out.print(proof.get(i)); if (i + 1 < proof.size()) System.out.print("  "); }
        System.out.println(" ]");

        boolean ok = mTree.verifyProof(targetTx, proof, root);
        System.out.println("Validação: " + (ok ? "Validated" : "False"));

        List<MerkleProofStep> badProof = tamperFirstStep(proof);
        boolean okBad = mTree.verifyProof(targetTx, badProof, root);
        System.out.println("Validação (prova adulterada): " + (okBad ? "Validated" : "False"));

        warmupValidate(mTree, targetTx, proof, root, 5_000);
        double avgValidNs = benchValidate(mTree, targetTx, proof, root, iters);

        warmupValidate(mTree, targetTx, badProof, root, 5_000);
        double avgInvalidNs = benchValidate(mTree, targetTx, badProof, root, iters);

        warmupBruteForce(txList, digestUtils, root, 50);
        double avgBruteNs = benchBruteForce(txList, digestUtils, root, 200);

        System.out.println("\n=== Resultados (médias) ===");
        System.out.printf("Validar prova VÁLIDA  : %.2f µs/op (%.2f ns)%n", avgValidNs / 1_000.0, avgValidNs);
        System.out.printf("Validar prova FALSA   : %.2f µs/op (%.2f ns)%n", avgInvalidNs / 1_000.0, avgInvalidNs);
        System.out.printf("Brute force (rebuild) : %.2f ms/op (%.2f ns)%n", avgBruteNs / 1_000_000.0, avgBruteNs);
        System.out.printf("Speedup vs brute (válida): %.1fx%n", (avgBruteNs / avgValidNs));
        System.out.printf("Speedup vs brute (falsa) : %.1fx%n", (avgBruteNs / avgInvalidNs));
    }

    private static int parseIntOr(String[] args, int pos, int def) {
        if (args.length > pos) { try { return Integer.parseInt(args[pos]); } catch (NumberFormatException ignore) {} }
        return def;
    }

    // gera strings aleatórias distintas (hex)
    private static List<String> generateRandomDistinctTx(int count, int bytesPerTx) {
        SecureRandom rng = new SecureRandom();
        Set<String> seen = new HashSet<>(count * 2);
        List<String> out = new ArrayList<>(count);
        byte[] buf = new byte[bytesPerTx];
        while (out.size() < count) {
            rng.nextBytes(buf);
            String s = toHex(buf);
            if (seen.add(s)) out.add(s);
        }
        return out;
    }

    // hex para bytes aleatórios
    private static String toHex(byte[] b) {
        final char[] HEX = "0123456789abcdef".toCharArray();
        char[] c = new char[b.length * 2];
        for (int i = 0, j = 0; i < b.length; i++) { int v = b[i] & 0xFF; c[j++] = HEX[v >>> 4]; c[j++] = HEX[v & 0x0F]; }
        return new String(c);
    }

    // muda 1 nibble do 1º passo 
    private static List<MerkleProofStep> tamperFirstStep(List<MerkleProofStep> proof) {
        List<MerkleProofStep> out = new ArrayList<>(proof.size());
        for (int i = 0; i < proof.size(); i++) {
            MerkleProofStep s = proof.get(i);
            if (i == 0) out.add(new MerkleProofStep(flipLastNibble(s.siblingHash), s.siblingPosition));
            else out.add(s);
        }
        return out;
    }

    // troca o último nibble de um hex
    private static String flipLastNibble(String hex) {
        if (hex == null || hex.isEmpty()) return hex;
        char[] h = hex.toCharArray();
        char c = Character.toLowerCase(h[h.length - 1]);
        h[h.length - 1] = (c == 'f') ? '0' : (char)(c + 1);
        return new String(h);
    }

    private static void warmupValidate(MerkleTree t, String tx, List<MerkleProofStep> p, String root, int iters) {
        for (int i = 0; i < iters; i++) t.verifyProof(tx, p, root);
    }

    private static double benchValidate(MerkleTree t, String tx, List<MerkleProofStep> p, String root, int iters) {
        long start = System.nanoTime(); int ok = 0;
        for (int i = 0; i < iters; i++) if (t.verifyProof(tx, p, root)) ok++;
        long end = System.nanoTime(); return (end - start) * 1.0 / iters;
    }

    private static void warmupBruteForce(List<String> txs, DigestUtils d, String root, int iters) {
        for (int i = 0; i < iters; i++) bruteForceValidate(txs, d, root);
    }

    // benchmark brute force 
    private static double benchBruteForce(List<String> txs, DigestUtils d, String root, int iters) {
        long start = System.nanoTime(); int ok = 0;
        for (int i = 0; i < iters; i++) if (bruteForceValidate(txs, d, root)) ok++;
        long end = System.nanoTime(); return (end - start) * 1.0 / iters;
    }

    // brute force validação 
    private static boolean bruteForceValidate(List<String> txs, DigestUtils d, String expectedRoot) {
        MerkleTree tmp = new MerkleTree(new ArrayList<>(txs), d);
        String r = tmp.getRootHash();
        return expectedRoot != null && expectedRoot.equals(r);
    }
}