package com.wrbug.wkcwallet.decode;

import com.wrbug.wkcwallet.entry.KeystoreInfoBean;
import com.wrbug.wkcwallet.util.JsonHelper;
import org.ethereum.crypto.HashUtil;
import org.spongycastle.crypto.generators.SCrypt;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created by host on 2018/3/31.
 */
public class Decoder {

    private static AtomicInteger sCounter = new AtomicInteger();

    public static void main(String[] args) throws FileNotFoundException {
        Config config = Config.get("config.json");
        KeystoreInfoBean bean = getKeyParamter(config);
        final String ciphertext = bean.getCrypto().getCiphertext();
        final String salt = bean.getCrypto().getKdfparams().getSalt();
        final int n = bean.getCrypto().getKdfparams().getN();
        final int r = bean.getCrypto().getKdfparams().getR();
        final int p = bean.getCrypto().getKdfparams().getP();
        final int dkLen = bean.getCrypto().getKdfparams().getDklen();
        final String mac = bean.getCrypto().getMac();

        final PasswordGenerator passwordGenerator = new PasswordGenerator(config);
        sCounter.set(0);

        int threadCount = config.threadCount;
        final int threadSize = (int) (passwordGenerator.getTotalCount() / threadCount);
        ExecutorService service = Executors.newFixedThreadPool(threadCount);
        final String dirPath = System.currentTimeMillis() + "";
        File dir = new File(dirPath);
        dir.mkdir();
        for (int i = 0; i < threadCount; i++) {
            final int finalI = i;
            service.submit(new Callable<Object>() {
                @Override
                public Object call() throws Exception {
                    int start = finalI * threadSize;
                    int end = (finalI + 1) * threadSize;
                    File file = new File(dirPath ,finalI + ".txt");
                    BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(file));
                    for (int j = start; j < end; j++) {
                        String pIt = passwordGenerator.get(j);
                        if (check(ciphertext, salt, n, r, p, dkLen, pIt, mac)) {
                            writeResult("password.txt", "password" + pIt);
                            System.exit(0);
                            return null;
                        } else {
                            outputStream.write((pIt + "\n").getBytes());
                        }
                    }
                    outputStream.flush();
                    outputStream.close();
                    return null;
                }
            });
        }
        service.shutdown();
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

    private static String get(List<String> list, int index) {
        int in = sCounter.incrementAndGet();
        int size = list.size();
        double percent = ((double) in) / size;
        System.out.println(percent);
        return list.get(index);
    }

    private static boolean check(String ciphertext, String salt, int n, int r, int p, int dkLen, String password, String mac) {
        byte[] derivedkey = SCrypt.generate(password.getBytes(), Hex.decode(salt), n, r, p, dkLen);
        byte[] vk = Arrays.copyOfRange(derivedkey, 16, 32);
        return mac.equals(Hex.toHexString(HashUtil.sha3(Arrays.concatenate(vk, Hex.decode(ciphertext)))));
    }
}
