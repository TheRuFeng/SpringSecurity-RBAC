package com.youngwind.security.oauth2.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

/**
 * @author WangBingchen
 * @since 2021-08-21
 */
@Configuration
public class OAuth2ServerConfig {

    private static final String DEMO_RESOURCE_ID = "demo";

    /**
     * 只有配置了ResourceServerConfigurerAdapter filterChain才会走 OAuth2AuthenticationProcessingFilter
     */
    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) {
            resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/test/hasAuthority").hasAuthority("ADMIN")
                    .anyRequest().authenticated();//配置order访问控制，必须认证过后才可以访问

        }
    }


    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        AuthenticationManager authenticationManager;

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
            endpoints
                    .authenticationManager(authenticationManager)
                    // jwt方式存储token
                    .tokenStore(jwtTokenStore())
                    .accessTokenConverter(accessTokenConverter())
                    .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
        }

        // 配置client，此处为配置到内存中
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // password 方案一：明文存储，用于测试，不能用于生产
            String finalSecret = "123456";
            // password 方案二：用 BCrypt 对密码编码
            // String finalSecret = new BCryptPasswordEncoder().encode("123456");
            // 配置两个客户端,一个用于password认证一个用于client认证
            clients.inMemory().withClient("client_1")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("client_credentials", "refresh_token")
                    .scopes("select")
                    .authorities("oauth2")
                    .secret(finalSecret)
                    .and().withClient("client_2")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("select")
                    .authorities("oauth2")
                    .secret(finalSecret);

            // 数据库配置client方式：clients.withClientDetails(new JdbcClientDetailsService(datasource));
        }

        /**
         * 对Jwt签名时，增加一个密钥
         * JwtAccessTokenConverter：对Jwt来进行编码以及解码的类
         */
        @Bean
        public JwtAccessTokenConverter accessTokenConverter() {
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey("test-secret");
            return converter;
        }

        /**
         * 设置token 由Jwt产生，不使用默认的透明令牌
         */
        @Bean
        public JwtTokenStore jwtTokenStore() {
            return new JwtTokenStore(accessTokenConverter());
        }

    }

}
