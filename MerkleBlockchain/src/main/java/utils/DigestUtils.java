package utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class DigestUtils {

    final static int SEED = 0x9747b28c;
    private static int flag = 0;

    MessageDigest digest = null;

    public DigestUtils(String algoType) throws NoSuchAlgorithmException {
        if (algoType.equalsIgnoreCase("MurmurHash2")) {
            flag = 1;
        } else {
            digest = MessageDigest.getInstance(algoType);
        }
    }

    public String getHash(String data) {
        if (flag == 1) {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            final byte[] hashbytes = MurmurHash2hash32(dataBytes, SEED );
            return bytesToHex(hashbytes);
        } else {
            final byte[] hashbytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            String sha3Hex = bytesToHex(hashbytes);
            return sha3Hex;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public List<String> getHashList(List<String> transactions) {
        List<String> hashes = new ArrayList<>();
        for (String tx : transactions) {
            String hash = getHash(tx);
            hashes.add(hash);
        }
        return hashes;
    }

    private byte[] MurmurHash2hash32(byte[] data, int seed) {
        int m = 0x5bd1e995;
        int r = 24;

        int len = data.length;
        int h = seed ^ len;
        int i = 0;

        while (len >= 4) {
            int k = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8)
                    | ((data[i + 2] & 0xFF) << 16) | ((data[i + 3] & 0xFF) << 24);

            k *= m;
            k ^= k >>> r;
            k *= m;

            h *= m;
            h ^= k;

            i += 4;
            len -= 4;
        }
        switch (len) {
            case 3:
                h ^= (data[i + 2] & 0xFF) << 16;
            case 2:
                h ^= (data[i + 1] & 0xFF) << 8;
            case 1:
                h ^= (data[i] & 0xFF);
                h *= m;
        }
        h ^= h >>> 13;
        h *= m;
        h ^= h >>> 15;
        return intToBytesLE(h);
    }
    //see also
    //https://commons.apache.org/proper/commons-codec/jacoco/org.apache.commons.codec.digest/MurmurHash2.java.html

    // Little-Endian (least significant byte first — used in MurmurHash):
    public static byte[] intToBytesLE(int value) {
        return new byte[]{
            (byte) value,
            (byte) (value >> 8),
            (byte) (value >> 16),
            (byte) (value >> 24)
        };
    }
}
