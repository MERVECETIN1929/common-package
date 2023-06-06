package com.kodlamaio.commonpackage.utils.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeycloakJwtRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final static String ROLE_PREFİX="ROLE_";
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        return extractRoles(source);
    }
    private Collection<GrantedAuthority> extractRoles(Jwt jwt){
        var clains=jwt.getClaims();
        var realmAccess=(Map<String,Object>) clains.getOrDefault("realm_access", Collections.emptyMap());
        var roles =(List<String>) realmAccess.getOrDefault("roles",Collections.emptyList());
        return roles.stream().map(role-> new SimpleGrantedAuthority(ROLE_PREFİX+role)).collect(Collectors.toList());
    }
}
