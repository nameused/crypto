package org.github.common.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class FileUtil {

    /**
     * 字节数组写入文件
     * @param path
     * @param data
     */
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

    /**
     * 读取文件获取字节数组形式
     * @param path
     * @return
     * @throws Exception
     */
    public static byte[] readFile(String path) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(path);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        return bytes;
    }

    /**
     * 字符串写入文件
     * @param path
     * @param content
     */
    public static void writeFile(String path,String content) throws Exception{
        File txt=new File(path);
        if(!txt.exists()){
            txt.createNewFile();
        }
        byte bytes[];
        bytes=content.getBytes();
        int b=bytes.length;
        //是字节的长度，不是字符串的长度
        FileOutputStream fos=new FileOutputStream(txt);
        fos.write(bytes,0,b);
        fos.close();
    }

}
