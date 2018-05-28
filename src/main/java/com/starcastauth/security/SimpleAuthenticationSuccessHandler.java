/**
 * 
 */
package com.starcastauth.security;

import static com.starcastauth.security.SecurityConstants.HEADER_STRING;
import static com.starcastauth.security.SecurityConstants.TOKEN_PREFIX;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;


/**
 * @author Ram Krishna
 *
 */
@Component
public class SimpleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication authentication)
			throws IOException, ServletException {
		User jwtUser = (User) authentication.getPrincipal();
		String token = jwtTokenUtil.generateToken(jwtUser);
		res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) authentication.getAuthorities();
		authorities.forEach(authority -> {
			if(authority.getAuthority().equals("USER")) {
				try {
					redirectStrategy.sendRedirect(req, res, "/admin/user");
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if(authority.getAuthority().equals("ADMIN")) {
				try {
					redirectStrategy.sendRedirect(req, res, "/admin/home");
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
	            throw new IllegalStateException();
	        }
		});
		
	}
 
}
