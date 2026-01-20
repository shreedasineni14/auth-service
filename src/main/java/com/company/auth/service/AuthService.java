package com.company.auth.service;

import com.company.auth.dto.LoginRequest;
import com.company.auth.dto.RegisterRequest;

public interface AuthService {

    void register(RegisterRequest request);
    
    String login(LoginRequest request);


}
  