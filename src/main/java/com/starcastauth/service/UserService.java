package com.starcastauth.service;

import com.starcastauth.model.User;

public interface UserService {
	public User findUserByEmail(String email);
	public void saveUser(User user);
}
