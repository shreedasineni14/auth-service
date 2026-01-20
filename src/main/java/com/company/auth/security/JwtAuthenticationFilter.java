package com.company.auth.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.company.auth.entity.User;
import com.company.auth.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;
	private final UserRepository userRepository;

	public JwtAuthenticationFilter(JwtUtil jwtUtil, UserRepository userRepository) {
		this.jwtUtil = jwtUtil;
		this.userRepository = userRepository;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String uri = request.getRequestURI();

		return uri.startsWith("/api/auth/") || uri.startsWith("/swagger-ui") || uri.startsWith("/v3/api-docs");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String uri = request.getRequestURI();

		// ✅ ABSOLUTE BYPASS for auth & swagger
		if (uri.startsWith("/api/auth/") || uri.startsWith("/swagger-ui") || uri.startsWith("/v3/api-docs")) {

			filterChain.doFilter(request, response);
			return;
		}

		String authHeader = request.getHeader("Authorization");

		if (authHeader == null) {
		    filterChain.doFilter(request, response);
		    return;
		}

		// 🔥 REMOVE ALL Bearer occurrences (case-insensitive)
		String token = authHeader
		        .replaceAll("(?i)bearer", "")
		        .trim();

		if (token.isEmpty()) {
		    filterChain.doFilter(request, response);
		    return;
		}

		System.out.println("✅ CLEAN JWT => [" + token + "]");
		// 🔐 Extract username from token
		String username;
		try {
		    username = jwtUtil.extractUsername(token);
		} catch (Exception e) {
		    filterChain.doFilter(request, response);
		    return;
		}

		// ✅ Authenticate only if not already authenticated
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

		    User user = userRepository.findByUsername(username).orElse(null);

		    if (user != null) {

		        UsernamePasswordAuthenticationToken authentication =
		                new UsernamePasswordAuthenticationToken(
		                        user.getUsername(),
		                        null,
		                        Collections.singletonList(
		                                new org.springframework.security.core.authority.SimpleGrantedAuthority(
		                                        "ROLE_" + user.getRole()
		                                )
		                        )
		                );

		        authentication.setDetails(
		                new WebAuthenticationDetailsSource().buildDetails(request)
		        );

		        SecurityContextHolder.getContext().setAuthentication(authentication);
		    }
		}

		// 🔁 Continue filter chain
		filterChain.doFilter(request, response);

	}
}
