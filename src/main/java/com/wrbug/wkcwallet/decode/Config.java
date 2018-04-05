package com.wrbug.wkcwallet.decode;

import com.wrbug.wkcwallet.util.JsonHelper;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;
import java.util.Scanner;

/**
 * Created by host on 2018/4/4.
 */
public class Config {
    public String keyStore;
    public String prefix;
    public String surfix;
    public List<Frag> letters;
    public int threadCount;

    public static class Frag {
        public int count;
        public String content;
    }

    public static Config get(String path) throws FileNotFoundException {
        Scanner scanner = new Scanner(new File(path));
        StringBuilder stringBuilder = new StringBuilder();
        while (scanner.hasNextLine()) {
            stringBuilder.append(scanner.nextLine());
        }
        return JsonHelper.fromJson(stringBuilder.toString(), Config.class);
    }
}
