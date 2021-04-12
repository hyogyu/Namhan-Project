package com.hyogyu;

import static com.hyogyu.Security.SecurityUtils.*;

import java.util.Scanner;

public class Main {

	public static String str;
	
	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);
		str = sc.nextLine();
		
		System.out.println("입력된 문자 : " + str);
		System.out.println("===================================");
		
		System.out.println("MD5 : " + md5(str));
		System.out.println("SHA-256 : " + sha256(str));
		
		String encrypted = encryptAES256(str, "my key");
		System.out.println("AES-256 암호화 : " + encrypted);
		System.out.println("AES-256 복호화 : " + decryptAES256(encrypted, "my key"));
	}
	
}
