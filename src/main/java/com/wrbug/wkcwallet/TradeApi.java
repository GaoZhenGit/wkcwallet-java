package com.wrbug.wkcwallet;

import com.wrbug.wkcwallet.entry.KeystoreInfoBean;
import com.wrbug.wkcwallet.util.JsonHelper;
import org.ethereum.wallet.CommonWallet;
import org.ethereum.wallet.Wallet;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by Administrator on 2018/3/30.
 */
public class TradeApi {
    public static void main(String[] args) {
        String keystore = "{\"address\":\"48d3a5ba74fea96ae1035c2310e3a595fde34a6c\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"1c63a3fbb4338c23b970cd9db76fb153d1f55fea64be2aab13c18cd1eb73f80c\",\"cipherparams\":{\"iv\":\"c08d068d03fad283440e58fa3bf8dbdb\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":4096,\"p\":6,\"r\":8,\"salt\":\"096353dca1ac6a11335653eabc01a24b307f0ea9d7f3183a4f9441cb790cab1f\"},\"mac\":\"2dacf78d2dba3241fe0466a589a9527399bc5e23580d6eea308ed645b9122995\"},\"id\":\"555e5b94-fd95-47bb-a48b-cc00cda1dc98\",\"version\":3}";
        Map json = JsonHelper.fromJson(keystore, Map.class);

        List<String> password = getPassword("Lin", "5354", 3);
        int size = password.size();
        for (int i = 0; i < size; i++) {
            String p = password.get(i);
            String percent = String.valueOf(((double) i) / size);
            System.out.println(p + ":" + percent);
            boolean result = veryfy(json, p);
            if (result) {
                System.out.println("password:" + p);
                System.exit(0);
            }
        }
        System.out.println("no password");
    }

    private static List<String> getPassword(String prefix, String sufFix, int count) {
        List<String> core = getPassword2(count);
        for (int i = 0; i < core.size(); i++) {
            String o = core.get(i);
            core.set(i, prefix + o + sufFix);
        }
        return core;
    }

    private static List<String> getPassword2(int count) {
        if (count == 1) {
            return getLetters();
        } else {
            List<String> letters = getLetters();
            List<String> up = getPassword2(count - 1);
            List<String> result = new ArrayList<>(letters.size() * up.size());
            for (int i = 0; i < letters.size(); i++) {
                for (int j = 0; j < up.size(); j++) {
                    result.add(letters.get(i) + up.get(j));
                }
            }
            return result;
        }
    }

    private static List<String> getLetters() {
        int count = 26;
        List<String> letter = new ArrayList<>();
        for (int i = 0, j = 'a'; i < count; i++, j++) {
            letter.add(Character.toString((char) j));
        }

//        for (int i = letter.size(), j = 0; j < count; i++, j++) {
//            letter.add(letter.get(j).toUpperCase());
//        }
        return letter;
    }

    private static boolean veryfy(String keyStore, String password) {
        KeystoreInfoBean keystoreInfo = JsonHelper.fromJson(keyStore, KeystoreInfoBean.class);
        if (keystoreInfo == null) {
//            System.out.println("钱包文件不正确");
            return false;
        }
        try {
            Wallet wallet = CommonWallet.fromV3(keyStore, password);
            return wallet != null;
        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//            System.out.println("钱包密码错误");
            return false;
        }
    }

    private static boolean veryfy(Map map, String password) {
        try {
            Wallet wallet = CommonWallet.fromV3(map, password);
            return wallet != null;
        } catch (GeneralSecurityException e) {
//            e.printStackTrace();
//            System.out.println("钱包密码错误");
            return false;
        }
    }
}
