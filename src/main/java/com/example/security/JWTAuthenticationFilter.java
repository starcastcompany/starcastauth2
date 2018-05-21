package com.example.security;


import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
    private JwtTokenUtil jwtTokenUtil;
	
	private AuthenticationManager authenticationManager;

	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, ApplicationContext applicationContext) {
		this.authenticationManager = authenticationManager;
		this.jwtTokenUtil = (JwtTokenUtil) applicationContext.getBean("jwtTokenUtil");
	}
	
	/**
	 * @return the jwtTokenUtil
	 */
	public JwtTokenUtil getJwtTokenUtil() {
		return jwtTokenUtil;
	}

	/**
	 * @param jwtTokenUtil the jwtTokenUtil to set
	 */
	public void setJwtTokenUtil(JwtTokenUtil jwtTokenUtil) {
		this.jwtTokenUtil = jwtTokenUtil;
	}



	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {
		try {
			if (!req.getMethod().equals("POST")) {
	            throw new AuthenticationServiceException("Authentication method not supported: " + req.getMethod());
	        }
	        //String username = obtainUsername(req);
			String username = req.getParameter("email");
	        String password = obtainPassword(req);
	        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		    return authenticationManager.authenticate(token);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		//JwtUser jwtUser = (JwtUser) auth.getPrincipal();
		/*User jwtUser = (User) auth.getPrincipal();
		String token = jwtTokenUtil.generateToken(jwtUser);
		res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);*/
		chain.doFilter(req, res);
	}
}
