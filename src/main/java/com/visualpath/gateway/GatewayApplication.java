package com.visualpath.gateway;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.ribbon.RibbonClientHttpRequestFactory;
import org.springframework.cloud.netflix.ribbon.SpringClientFactory;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.csrf.CsrfFilter;

@SpringBootApplication
@EnableZuulProxy
@EnableDiscoveryClient
@EnableOAuth2Sso
public class GatewayApplication extends WebSecurityConfigurerAdapter{

	
	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}
	
	 @Override
	    public void configure(HttpSecurity http) throws Exception {
	        http.authorizeRequests().antMatchers("/uaa/**", "/login").permitAll().anyRequest().authenticated()
	            .and()
	            .csrf().disable();/*.requireCsrfProtectionMatcher(csrfRequestMatcher()).csrfTokenRepository(csrfTokenRepository())
	            .and()
	            .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
	            .addFilterAfter(oAuth2AuthenticationProcessingFilter(), AbstractPreAuthenticatedProcessingFilter.class)
	            .logout().permitAll()
	            .logoutSuccessUrl("/");*/
	    }

	
	
	// allow to specify how to contact the token management services on the authorization server
   /* @Primary
	@Bean
    public RemoteTokenServices tokenServices() {
        RemoteTokenServices tokenServices = new RemoteTokenServices();
        // to validate token received
        tokenServices.setCheckTokenEndpointUrl("http://localhost:9191/uaa/oauth/check_token");
        //
        tokenServices.setClientId("edge-service");
        tokenServices.setClientSecret("secret");
        return tokenServices;
    }*/
    /*

    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/ecommerce");
        dataSource.setUsername("root");
        dataSource.setPassword("2023*Laddu");
        return dataSource;
    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
       // converter.setSigningKey("123");
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        //return new JdbcTokenStore(dataSource()); // this way TokenStore will know how to connect to jdbc to look up the tokens
    	return new JwtTokenStore(accessTokenConverter());
    }
*/
	@Bean
	UserInfoRestTemplateCustomizer userInfoRestTemplateCustomizer(SpringClientFactory springClientFactory) {
	    return template -> {
	        AccessTokenProviderChain accessTokenProviderChain = Stream
	                .of(new AuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
	                        new ResourceOwnerPasswordAccessTokenProvider(), new ClientCredentialsAccessTokenProvider())
	                .peek(tp -> tp.setRequestFactory(new RibbonClientHttpRequestFactory(springClientFactory)))
	                .collect(Collectors.collectingAndThen(Collectors.toList(), AccessTokenProviderChain::new));
	        template.setAccessTokenProvider(accessTokenProviderChain);
	    };
	}
}

