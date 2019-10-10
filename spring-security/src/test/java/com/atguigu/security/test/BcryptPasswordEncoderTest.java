package com.atguigu.security.test;


import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BcryptPasswordEncoderTest {

	@Test
	public void test() {
		
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		//$2a$10$AmMJ8Yg5mLlAvhiM/duwluxDGveRHPM9q/9pAWYPM42kgw.Q0rIr.
		//$2a$10$E3Ddj02yfirwHIW4vZCGJeAqjSsrjJnY8WUN2sLfZrg8wE3bizFiO
		System.out.println(encoder.encode("123456"));
		
	}

}
