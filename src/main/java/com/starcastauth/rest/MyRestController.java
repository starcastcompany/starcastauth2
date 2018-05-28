/**
 * 
 */
package com.starcastauth.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Ram Krishna
 *
 */
@RestController
@RequestMapping("/protected")
public class MyRestController {
	
	@RequestMapping(value="/admin", method = RequestMethod.GET)
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<?> getProtectedAdminGreeting() {
        return ResponseEntity.ok("Greetings from admin protected method!");
    }
	
	@RequestMapping(value="/user", method = RequestMethod.GET)
    @PreAuthorize("hasAuthority('USER')")
    public ResponseEntity<?> getProtectedUserGreeting() {
        return ResponseEntity.ok("Greetings from user protected method!");
    }


}
