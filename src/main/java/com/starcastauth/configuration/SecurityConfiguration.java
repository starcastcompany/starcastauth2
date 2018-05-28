package com.starcastauth.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.starcastauth.security.JWTAuthenticationFilter;
import com.starcastauth.security.JwtAuthenticationEntryPoint;
import com.starcastauth.security.JwtAuthorizationTokenFilter;
import com.starcastauth.security.JwtTokenUtil;
import com.starcastauth.security.SimpleAuthenticationFailureHandler;
import com.starcastauth.security.SimpleAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Autowired
	private DataSource dataSource;
	
	@Value("${spring.queries.users-query}")
	private String usersQuery;
	
	@Value("${spring.queries.roles-query}")
	private String rolesQuery;
	
	@Autowired
	private SimpleAuthenticationSuccessHandler successHandler;
	
	@Autowired
	private SimpleAuthenticationFailureHandler failureHandler;
	
	@Autowired
    private JwtTokenUtil jwtTokenUtil;
	
	@Value("${jwt.header}")
    private String tokenHeader;

    @Value("${jwt.route.authentication.path}")
    private String authenticationPath;

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.
			jdbcAuthentication()
				.usersByUsernameQuery(usersQuery)
				.authoritiesByUsernameQuery(rolesQuery)
				.dataSource(dataSource)
				.passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.
			authorizeRequests()
				.antMatchers("/").permitAll()
				.antMatchers("/login").permitAll()
				.antMatchers("/inValidLogin").permitAll()
				.antMatchers("/registration").permitAll()
				.antMatchers("/admin/home/**").hasAuthority("ADMIN")
				.antMatchers("/admin/user/**").hasAuthority("USER")
				.anyRequest().authenticated().and().csrf().disable().formLogin().successHandler(successHandler)
				.loginPage("/login").failureUrl("/login?error=true")
				//.defaultSuccessUrl("/admin/home")
				.usernameParameter("email")
				.passwordParameter("password")
				.and().logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/").and().exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
				.accessDeniedPage("/access-denied");
		
		http.addFilterBefore(new JWTAuthenticationFilter(authenticationManager(), getApplicationContext(), failureHandler), UsernamePasswordAuthenticationFilter.class);
		
		// Custom JWT based security filter
        JwtAuthorizationTokenFilter authenticationTokenFilter = new JwtAuthorizationTokenFilter(userDetailsService(), jwtTokenUtil, tokenHeader);
        http
            .addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        // disable page caching
        http
            .headers()
            .frameOptions().sameOrigin()  // required to set for H2 else H2 Console will be blank.
            .cacheControl();
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		/*web
        .ignoring()
        .antMatchers(
            HttpMethod.POST,
            authenticationPath
        );*/
        
	    web
	       .ignoring()
	       .antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
	}

}