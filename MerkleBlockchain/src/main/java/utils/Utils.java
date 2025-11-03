package utils;

import java.util.List;

public class Utils {
    public static List<String> extendTillPowerOf2(List<String> txs, String dummyData) {
        while (true) {
            int size = txs.size();
            if ((size & (size - 1)) == 0)
                break;
            txs.add(dummyData);
            
        }
        return txs;
    }

    public static boolean compare(String s1, String s2) {
        return s1.compareTo(s2) < 0;
    }

}
