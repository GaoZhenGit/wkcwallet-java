package com.wrbug.wkcwallet;

import com.wrbug.wkcwallet.entry.KeystoreInfoBean;
import com.wrbug.wkcwallet.util.JsonHelper;
import org.ethereum.crypto.HashUtil;
import org.spongycastle.crypto.generators.SCrypt;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Created by host on 2018/3/31.
 */
public class Decoder {

    public static void main(String[] args) throws FileNotFoundException {
        Config config = getConfig("config.json");
        KeystoreInfoBean bean = getKeyParamter(config);
        String ciphertext = bean.getCrypto().getCiphertext();
        String salt = bean.getCrypto().getKdfparams().getSalt();
        int n = bean.getCrypto().getKdfparams().getN();
        int r = bean.getCrypto().getKdfparams().getR();
        int p = bean.getCrypto().getKdfparams().getP();
        int dkLen = bean.getCrypto().getKdfparams().getDklen();
        String mac = bean.getCrypto().getMac();

        List<String> list = getPassword(config);
        int size = list.size();
        for (int i = 0; i < size; i++) {
            double percent = ((double)i) / size;
            String pIt = list.get(i);
            System.out.println(pIt + ":" + percent);
            if (check(ciphertext, salt, n, r, p, dkLen, pIt, mac)) {
                writeResult("password.txt", "password" + pIt);
                return;
            }
        }
        writeResult("password.txt", "no password");
    }

    private static void writeResult(String path, String content) throws FileNotFoundException {
        System.out.println(content);
        PrintWriter printWriter = new PrintWriter(path);
        printWriter.print(content);
        printWriter.flush();
        printWriter.close();
    }

    private static KeystoreInfoBean getKeyParamter(Config config) {
        return JsonHelper.fromJson(config.keyStore, KeystoreInfoBean.class);
    }

    private static List<String> getPassword(Config config) {
        List<String> core = getPassword2(config.bitCount, config);
        for (int i = 0; i < core.size(); i++) {
            String o = core.get(i);
            core.set(i, config.prefix + o + config.surfix);
        }
        return core;
    }

    private static List<String> getPassword2(int count, Config config) {
        if (count == 1) {
            return getLetters(config);
        } else {
            List<String> letters = getLetters(config);
            List<String> up = getPassword2(count - 1, config);
            List<String> result = new ArrayList<>(letters.size() * up.size());
            for (int i = 0; i <= letters.size(); i++) {
                if (i == 0) {
                    for (int j = 0; j < up.size(); j++) {
                        result.add(up.get(j));
                    }
                } else {
                    for (int j = 0; j < up.size(); j++) {
                        result.add(letters.get(i - 1) + up.get(j));
                    }
                }
            }
            return result;
        }
    }

    private static List<String> getLetters(Config config){
        List<String> result = new ArrayList<>(config.letters.length());
        for (int i = 0; i < config.letters.length(); i++) {
            result.add(String.valueOf(config.letters.charAt(i)));
        }
        return result;
    }

    private static Config getConfig(String path) throws FileNotFoundException {
        File file = new File(path);
        Scanner scanner = new Scanner(file);
        StringBuilder stringBuilder = new StringBuilder();
        while (scanner.hasNextLine()){
            stringBuilder.append(scanner.nextLine());
        }
        return JsonHelper.fromJson(stringBuilder.toString(), Config.class);
    }

    private static boolean check(String ciphertext,String salt,int n, int r, int p, int dkLen, String password, String mac) {
        byte[] derivedkey = SCrypt.generate(password.getBytes(), Hex.decode(salt), n, r, p, dkLen);
        byte[] vk = Arrays.copyOfRange(derivedkey, 16, 32);
        return mac.equals(Hex.toHexString(HashUtil.sha3(Arrays.concatenate(vk, Hex.decode(ciphertext)))));
    }

    private static class Config {
        public String keyStore;
        public String prefix;
        public String surfix;
        public String letters;
        public int bitCount;
    }
}
