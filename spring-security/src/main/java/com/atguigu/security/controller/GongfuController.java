package com.atguigu.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * 注意：
 * 	开发中使用springsecurity
 * 		-pom文件中引入依赖
 * 		-在web.xml配置springsecurity filter
 * 		-编写springsecurity配置类：在配置类中编写权限验证规则。。
 * 		-在controller中
 * 			方法上使用@PreAuthorize("hasAnyRole('ADMIN')") 对方法进行授权绑定
* @Description
* @author Mark 
* @version
* @date 2019年9月20日下午9:10:34
*
 */
@Controller
public class GongfuController {
	
	@PreAuthorize("hasAnyRole('ADMIN')")
	@GetMapping("/level1/1")
	public String leve11Page(){
		return "/level1/1";
	}
	@PreAuthorize("hasAnyRole('MANAGER' , 'TL - 组长')")
	@GetMapping("/level1/2")
	public String leve12Page(){
		return "/level1/2";
	}
	@PreAuthorize("hasAnyAuthority('user:delete','user:add')")
	@GetMapping("/level1/3")
	public String leve13Page(){
		return "/level1/3";
	}
	
	@GetMapping("/level2/{path}")
	public String leve2Page(@PathVariable("path")String path){
		return "/level2/"+path;
	}
	
	@GetMapping("/level3/{path}")
	public String leve3Page(@PathVariable("path")String path){
		return "/level3/"+path;
	}

}
