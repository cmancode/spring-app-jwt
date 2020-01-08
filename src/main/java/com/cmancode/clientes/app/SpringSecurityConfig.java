package com.cmancode.clientes.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cmancode.clientes.app.outh.handler.LoginSucessHandler;
import com.cmancode.clientes.app.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	
		
	@Autowired
	private LoginSucessHandler seccessHandler;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.authorizeRequests()
		.antMatchers("/","/clientes","/css/**","/img/**","/js/**", "/uploads/**", "/ver/**").permitAll() 
		/*.antMatchers("/cliente").hasAnyRole("ADMIN")
		.antMatchers("/cliente/**").hasAnyRole("ADMIN")
		.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
		.antMatchers("/factura/**").hasAnyRole("ADMIN")
		.antMatchers("/detalle/**").hasAnyRole("ADMIN")
		.antMatchers("/detalle/**").hasAnyRole("USER")*/
		.anyRequest().authenticated()
		.and()
		.formLogin()
			.successHandler(seccessHandler)
			.loginPage("/login").permitAll()
		.and()
		.logout().permitAll()
		.and().exceptionHandling().accessDeniedPage("/error_403");
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder build) throws Exception{
		
		build.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
	}

}
