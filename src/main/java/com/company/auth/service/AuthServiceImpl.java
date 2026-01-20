package com.company.auth.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.company.auth.dto.LoginRequest;
import com.company.auth.dto.RegisterRequest;
import com.company.auth.entity.Role;
import com.company.auth.entity.User;
import com.company.auth.repository.UserRepository;
import com.company.auth.security.JwtUtil;

@Service
public class AuthServiceImpl implements AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;

	public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtUtil = jwtUtil;
	}

	@Override
	public void register(RegisterRequest request) {

		if (userRepository.existsByUsername(request.getUsername())) {
			throw new RuntimeException("Username already exists");
		}

		User user = new User();
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(Role.ROLE_USER);

		userRepository.save(user);
	}

	@Override
	public String login(LoginRequest request) {

	    User user = userRepository.findByUsername(request.getUsername())
	            .orElseThrow(() -> new RuntimeException("Invalid credentials"));

	    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
	        throw new RuntimeException("Invalid credentials");
	    }

	    return jwtUtil.generateToken(user.getUsername());

	}

}
