package com.wrbug.wkcwallet.decode;

import com.wrbug.wkcwallet.util.JsonHelper;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Created by host on 2018/4/4.
 */
public class PasswordGenerator {
    private final int partCount;
    private List<List<String>> lettersPool;
    private long totalCount = 1;
    private int bitCount;
    private String preFix;
    private String surFix;
    private AtomicInteger counter;

    public PasswordGenerator(Config config) {
        //密码有多少段？
        partCount = config.letters.size();
        lettersPool = new ArrayList<>(partCount);
        for (int i = 0; i < partCount; i++) {
            Config.Frag frag = config.letters.get(i);
            List<String> partPool = new ArrayList<>(frag.count);
            for (int j = 0; j < frag.content.length(); j++) {
                partPool.add(String.valueOf(frag.content.charAt(j)));
            }
            for (int j = 0; j < frag.count; j++) {
                lettersPool.add(partPool);
            }
            totalCount *= Math.pow(frag.content.length(), frag.count);
            bitCount += frag.count;
        }
        preFix = config.prefix;
        surFix = config.surfix;
        counter = new AtomicInteger(0);
    }

    public int getBitCount() {
        return bitCount;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public String get(long index) {
        int curI = counter.incrementAndGet();
        double percent = ((double) curI) / totalCount;
        System.out.println(percent);

        long remider = index;
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = lettersPool.size() - 1; i >= 0; i--) {
            List<String> bitLetter = lettersPool.get(i);
            long in = remider % bitLetter.size();
            remider = remider / bitLetter.size();
            stringBuilder.insert(0, bitLetter.get((int) in));
        }
        stringBuilder.insert(0, preFix);
        stringBuilder.append(surFix);
        return stringBuilder.toString();
    }

    public static void main(String[] args) throws FileNotFoundException {
        File file = new File("config.json");
        Scanner scanner = new Scanner(file);
        StringBuilder stringBuilder = new StringBuilder();
        while (scanner.hasNextLine()) {
            stringBuilder.append(scanner.nextLine());
        }
        Config config = JsonHelper.fromJson(stringBuilder.toString(), Config.class);
        PasswordGenerator generator = new PasswordGenerator(config);
        generator.getTotalCount();
        for (int i = 0; i < generator.getTotalCount(); i++) {
            System.out.println(generator.get(i));
        }
    }
}
