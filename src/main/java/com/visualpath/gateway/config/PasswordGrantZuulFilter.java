package com.visualpath.gateway.config;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class PasswordGrantZuulFilter extends ZuulFilter {

    @Value("${security.oauth2.client.access-token-uri}")
    private String accessTokenUri;

    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;

    @Autowired
    private OAuth2ClientContext clientContext;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
    	System.out.println("should filter");
    	AccessTokenRequest clientctx = clientContext.getAccessTokenRequest();
    	String code = clientctx.getAuthorizationCode();
        RequestContext ctx = RequestContext.getCurrentContext();
       HttpServletRequest req = ctx.getRequest();
       System.out.println("host2"+req.getRequestURI());
       System.out.println(req.getRequestURI().contains("catalog"));
        return req.getRequestURI().contains("catalog");   	
        
            }

    @Override
    public Object run() {
    	
        RequestContext ctx = RequestContext.getCurrentContext();
        if (clientContext.getAccessToken() == null) {

            String header = ctx.getRequest().getHeader(HttpHeaders.AUTHORIZATION);

            String base64Credentials = header.substring("Basic".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), Charset.forName("UTF-8"));
            final String[] values = credentials.split(":", 2);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.put(HttpHeaders.AUTHORIZATION, Collections.singletonList("Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes())));

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "password");
            map.add("username", values[0]);
            map.add("password", values[1]);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            ResponseEntity<OAuth2AccessToken> response = new RestTemplate().postForEntity(accessTokenUri, request, OAuth2AccessToken.class);
            clientContext.setAccessToken(response.getBody());
        }

        ctx.addZuulRequestHeader(HttpHeaders.AUTHORIZATION, OAuth2AccessToken.BEARER_TYPE + " " + clientContext.getAccessToken().getValue());

        return null;
    }

}
