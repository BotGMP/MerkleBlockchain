package ubi;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import utils.DigestUtils;
import utils.Utils;

public class MerkleTree {
    public List<String> transactions;
    public MerkleNode root;
    DigestUtils digestUtils;
    int levels;

    public MerkleTree(List<String> transactions, DigestUtils digestUtils) {
        this.transactions = transactions;
        this.digestUtils = digestUtils;
        System.out.println("Initialize");
        transactions = Utils.extendTillPowerOf2(transactions, "");
        levels = (int) (Math.log(transactions.size()) / Math.log(2));
        System.out.println("Num. Transaction levels " + levels + "  transactions " + transactions.size());
        buildMerkleTree(transactions);
    }

    final void buildMerkleTree(List<String> transactions) {
        List<MerkleNode> nodes = MerkleNode.getLeafNodes(transactions, digestUtils);
        while (nodes.size() > 1) {
            List<MerkleNode> newNodes = new ArrayList<>();
            for (int i = 0; i < nodes.size(); i += 2) {
                newNodes.add(new MerkleNode(nodes.get(i), nodes.get(i + 1), digestUtils));
            }
            nodes = newNodes;
        }
        this.root = nodes.isEmpty() ? null : nodes.get(0);
    }

    public void printTree() {
        if (root == null) { System.out.println("(árvore vazia)"); return; }
        Queue<MerkleNode> q = new LinkedList<>();
        q.add(root);
        while (!q.isEmpty()) {
            int levelSize = q.size();
            for (int i = 0; i < levelSize; i++) {
                MerkleNode node = q.remove();
                System.out.print(node.hash + " ");
                if (node.left != null) q.add(node.left);
                if (node.right != null) q.add(node.right);
            }
            System.out.println();
        }
    }

    // pretty print 
    public void printTreePretty() { printTreePretty(8); }

    public void printTreePretty(int hashChars) {
        if (root == null) { System.out.println("(árvore vazia)"); return; }
        int height = getHeight(root);
        int totalSlots = 1 << (height - 1);
        int cellWidth = Math.max(3, hashChars) + 2;
        int totalWidth = totalSlots * cellWidth;

        List<MerkleNode> level = new ArrayList<>();
        level.add(root);
        int currentLevel = 0;

        while (!allNull(level) && currentLevel < height) {
            int nodes = level.size();
            int slotsPerNode = Math.max(1, totalSlots / nodes);
            int gap = slotsPerNode * cellWidth;
            int between = gap - hashChars;
            int leftMargin = Math.max(0, (totalWidth - nodes * (hashChars + between)) / 2);

            printSpaces(leftMargin);
            for (int i = 0; i < nodes; i++) {
                int leftPad = Math.max(0, (gap - hashChars) / 2);
                printSpaces(leftPad);
                String label = (level.get(i) == null) ? "·" : shorten(level.get(i).hash, hashChars);
                System.out.print(label);
                printSpaces(between);
            }
            System.out.println();

            if (currentLevel < height - 1) {
                printSpaces(leftMargin);
                for (int i = 0; i < nodes; i++) {
                    int leftPad = Math.max(0, (gap - hashChars) / 2) - 1;
                    if (leftPad < 0) leftPad = 0;
                    printSpaces(leftPad);
                    System.out.print(level.get(i) == null ? " " : "/");
                    int mid = Math.max(1, between + 2 - 2 * leftPad);
                    printSpaces(mid);
                    System.out.print(level.get(i) == null ? " " : "\\");
                    printSpaces(leftPad);
                }
                System.out.println();
            }

            List<MerkleNode> next = new ArrayList<>(nodes * 2);
            for (MerkleNode n : level) {
                if (n == null) { next.add(null); next.add(null); }
                else { next.add(n.left); next.add(n.right); }
            }
            level = next;
            currentLevel++;
        }
    }

    // verifica a prova
    public boolean verifyProof(String tx, List<MerkleProofStep> proof, String expectedRoot) {
        if (tx == null || expectedRoot == null || proof == null) return false;
        String h = digestUtils.getHash(tx);
        for (MerkleProofStep step : proof) {
            if (step == null || step.siblingHash == null) return false;
            if (Utils.compare(h, step.siblingHash)) h = digestUtils.getHash(h + step.siblingHash);
            else h = digestUtils.getHash(step.siblingHash + h);
        }
        return expectedRoot.equals(h);
    }

    // verifica a prova a partir do hash da folha
    public boolean verifyProofFromLeafHash(String leafHash, List<MerkleProofStep> proof, String expectedRoot) {
        if (leafHash == null || expectedRoot == null || proof == null) return false;
        String h = leafHash;
        for (MerkleProofStep step : proof) {
            if (step == null || step.siblingHash == null) return false;
            if (Utils.compare(h, step.siblingHash)) h = digestUtils.getHash(h + step.siblingHash);
            else h = digestUtils.getHash(step.siblingHash + h);
        }
        return expectedRoot.equals(h);
    }

    public String getRootHash() { return root == null ? null : root.hash; }

    // devolve a prova para a trancacao
    public List<MerkleProofStep> getProofForTx(String tx) {
        String leafHash = digestUtils.getHash(tx);
        if (root == null) return java.util.Collections.emptyList();
        List<MerkleProofStep> acc = new ArrayList<>();
        boolean found = buildProof(root, leafHash, acc);
        return found ? acc : java.util.Collections.emptyList();
    }

    // faz a procura recursiva e acumula a prova
    private boolean buildProof(MerkleNode node, String leafHash, List<MerkleProofStep> acc) {
        if (node == null) return false;
        if (node.left == null && node.right == null) return leafHash.equals(node.hash);
        if (buildProof(node.left, leafHash, acc)) { acc.add(new MerkleProofStep(node.right.hash, Direction.RIGHT)); return true; }
        if (buildProof(node.right, leafHash, acc)) { acc.add(new MerkleProofStep(node.left.hash, Direction.LEFT)); return true; }
        return false;
    }

    private static int getHeight(MerkleNode node) {
        if (node == null) return 0;
        int lh = getHeight(node.left), rh = getHeight(node.right);
        return Math.max(lh, rh) + 1;
    }

    private static boolean allNull(List<MerkleNode> nodes) {
        for (MerkleNode n : nodes) if (n != null) return false;
        return true;
    }

    private static void printSpaces(int n) { for (int i = 0; i < n; i++) System.out.print(' '); }

    private static String shorten(String s, int n) { return (s == null || s.length() <= n) ? s : s.substring(0, n); }

    public enum Direction { LEFT, RIGHT }

    public static class MerkleProofStep {
        public final String siblingHash;
        public final Direction siblingPosition;
        public MerkleProofStep(String siblingHash, Direction siblingPosition) {
            this.siblingHash = siblingHash; this.siblingPosition = siblingPosition;
        }
        @Override public String toString() {
            String shortHash = siblingHash == null ? "null" : (siblingHash.length() <= 8 ? siblingHash : siblingHash.substring(0, 8));
            return shortHash + "(" + siblingPosition + ")";
        }
    }
}