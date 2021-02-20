package org.github.common.utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class FileUtil {
    public static void saveFile(String path, byte[] data) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            fileOutputStream.write(data);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static byte[] readFile(String path) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(path);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        return bytes;
    }

}
