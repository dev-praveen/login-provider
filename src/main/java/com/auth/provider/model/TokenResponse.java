package com.auth.provider.model;

public record TokenResponse(String token, long expiresIn, String type, String scope) {}
