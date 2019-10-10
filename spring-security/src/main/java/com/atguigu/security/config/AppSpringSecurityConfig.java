package com.atguigu.security.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;

/**
	 *  1.导入练习的maven工程
	 *  2.早pom文件中导入SpringSecurity的依赖[3个]
	 *  3.在web.xml中配置SpringSecurity的代理filter
	 *  4.在项目中创建SpringSecurity的配置类继承
	 *  5.让配置类成为组件+启用SpringSecurity
	 *  @Configuration:代表配置类注解
	 *  @EnableWebSecurity:代表启用webSpringSecurity的注解
	 *  6.当访问项目的资源时，自动跳转到一个SpringSecurity自带的登录页面，则代表SpringSecurity已经配置成功
	* @Description
	* @author Mark 
	* @version
	* @date 2019年9月16日下午6:24:03
	* 实验1：
	* 		项目首页/登录页面  以及项目组的所有经验资源 希望SpringSecurity不用授权认证，所有人都可以访问
	 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)//启用更加细粒度的控制，控制方法映射的权限
public class AppSpringSecurityConfig extends WebSecurityConfigurerAdapter{
	
	//控制表单提交+请求认证授权
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//super.configure(http);//默认规则：访问时直接跳转到SpringSecurity的默认登录页面
		//实验6：基于角色和权限的访问控制
		//自定义认证授权规则：
		http.authorizeRequests()
			.antMatchers("/index.jsp" , "/layui/**").permitAll()//设置首页和静态资源所有人都可以访问
//			.antMatchers("/level1/*").hasAnyRole("SA - 软件架构师")//给具体的资源设置需要的权限或角色
//			.antMatchers("/level2/*").hasAnyRole("PM - 项目经理")
//			.antMatchers("/level3/*").hasAnyAuthority("CMO / CMS - 配置管理员")
			.anyRequest().authenticated();//设置其他的所有请求都需要验证:只要登录授权认证成功，那么就可以访问的所有的资源，除非资源设置了具体的权限要求
		//实验2.1：如果访问未授权的页面，默认显示403页面，希望给用户响应一个SpringSecurity默认登录页面
		//http.formLogin();
		//实验2.2：默认登录页面有框架提供，过于简单，希望跳转到项目自带的登录页面
		//实验3：设置自定义的登录表单提交的action地址，注意：1.action地址和loginProcessingUrl一样
		//       2.请求方式必须是post。3.SpringSecurity考虑安全问题表单提交必须携带token标志(防止表单重复提交，防止钓鱼网站)
		http.formLogin()
			.loginPage("/index.jsp")//设置自定义的登录页面
			.usernameParameter("uname")//设置登录表单的账号与name属性值，默认为username
			.passwordParameter("pwd")//设置登录表单的密码与name属性值，默认为password
			.loginProcessingUrl("/dologin")//设置提交登录请求的url地址，默认会交给SpringSecurity处理
			.defaultSuccessUrl("/main.html");//设置登录成功后要跳转的页面
		//如果实验3：提交登录请求 返回到index.jsp页面并携带参数？error，代表账号密码认证失败
		//在登录页面中可以通过${SPRING_SECURITY_LAST_EXCEPTION.message}获取错误信息
		//UsernamePasswordAuthenticationToken：账号密码认证的类
		//禁用SpringSecurity的csrf验证功能，框架默认开启，访问登录页面时框架会自动创建一个唯一的一个字符串设置到session域中
		//如果使用csrf功能：需要在登录页面的表单中获取唯一字符串以隐藏的形式设置，name的属性值必须是_csrf
		//http.csrf().disable();
		//实验5：默认注销方式
		//注意：1.请求当时必须为post 2.csrf如果开启了必须在表单中携带csrf的token  3.默认得注销请求的url：  logout
		//实验5.2 自定义注销方式
		http.logout()
			.logoutUrl("/user-logout")//自定义注销url地址
			.logoutSuccessUrl("/index.jsp");//注销成功的跳转页面
		//实验6.2：自定义异常处理，当页面在403时跳转到自定义页面
		//http.exceptionHandling().accessDeniedPage("/unauthed");
		http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
			
			@Override
			public void handle(HttpServletRequest request, HttpServletResponse response,
					AccessDeniedException accessDeniedException) throws IOException, ServletException {
				
				
				request.setAttribute("resource", request.getServletPath());//访问失败的资源
				request.setAttribute("errorMsg", accessDeniedException.getMessage());//访问失败的异常信息
				request.getRequestDispatcher("/unauthed").forward(request, response);//转发到错误页面 	
				
				
				
			}
		});
		//实验7：记住简单版【登录请求携带 remeber-me 参数 ，代码中开启remeberme功能】
		
		//用户登录成功，主体信息(用户信息+权限角色信息)默认保存到服务器内存的session中，一次会话有效
		//如果希望登陆之后的主体权限角色信息范围超过一次会话，可以开启springsecurity的记住我功能
		//http.rememberMe();//浏览器会接受到apringsecurity创建的remeberme的token持久化保存，下次打开浏览器只要携带token就可以直接访问之前有权访问的页面
		//服务器将token对应的权限信息保存到服务器内存中，如果服务器重启则失效【浏览器功能失效了】 
		//实验7.2：记住我数据库版
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		http.rememberMe().tokenRepository(tokenRepository);
		
	}
	@Autowired
	DataSource dataSource;
	@Autowired
	UserDetailsService userDetailsService;
	@Autowired
	PasswordEncoder passwordEncoder;
	
	//授权验证的账号密码+该角色的角色权限。。。
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		//super.configure(auth);系统默认的自带的授权认证规则
		//实验4.自定义用户信息
//		auth.inMemoryAuthentication()//在内存中设置账号密码+授权
//			.withUser("lisi").password("123456").roles("MANAGER" , "BOSS")//创建主体时：包括用户账号密码+角色权限
//			.and()
//			.withUser("zhangsan").password("123456").authorities("USER:ADD" , "USER:DELETE"); //设置一个用户信息+授权
			//设置角色权限时，无论调用roles还是authorities，底层都是调用了authorities实现的
		//role传入的字符串前默认会拼接：ROLE_前缀 表示角色，底层判断角色权限时本质时进行字符串的比较
		//实验8.1：基于 数据库数据的认证【登录信息和数据库数据进行比较，登录成功用户的权限角色从数据库中获取】
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);//如果使用UserDetailsService框架提供的实现类来完整主体信息的调查封装，表必须和它要求的一样
		//用户-角色-权限
		//登录时 springsecurity默认密码判断时不适用加密方式处理
		//实验8.2：MD5加密方式 基于数据库的角色认证
		//实验8.3：BCryptPasswordEncoder基于数据库角色认证
	}
	/**
	 * 向容器中配置bean的方式：
	 * 	1.在spring配置文件中使用<bean>标签配置
	 * 	2.在组件上使用注解配置
	 * 		Component,Repository(Mapper),Service,Controller,Configuration
	 * 	3.在方法上使用@bean注解配置
	 * 		标注的方法返回值会自动交给容器配置到容器中，方法必须写到组件上
	 */
	@Bean
	public BCryptPasswordEncoder getPasswordEncoder() {
		return new BCryptPasswordEncoder();
		
	}
	
}
