package com.auth.provider.model;

public record TokenRequest(String userName, String password, String scope) {}
