package org.github.common.utils;

import java.util.Calendar;
import java.util.Date;

public class CommUtil {


    /**
     * 获取当前时间n年后的时间
     * @param year
     * @return
     */
    public static Date getDate(int year){
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.YEAR,year);
        return calendar.getTime();
    }
}
