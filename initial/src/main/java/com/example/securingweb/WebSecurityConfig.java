package com.example.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * http.authorizeRequests() enables the restriction of access
     * .permitAll() allows all users to access the specified URLs
     * .anyRequest().authenticated() all other requests have to be authenticated
     * .formLogin() users can log in with a form based login
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                    .authenticationEntryPoint(spnegoEntryPoint())
                    .and()
                .authorizeRequests()
                    .antMatchers("/", "/home").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login").permitAll()
                    .and()
                .logout().permitAll()
                    .and()
                .addFilterBefore(
                        spnegoAuthenticationProcessingFilter(authenticationManagerBean()),
                        BasicAuthenticationFilter.class);
    }

    /**
     * if we're using a custom authentication filter that requires an authentication entry point
     * also works without, but I think it's probably better
     */
    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint("/login");
    }

    /**
     * authentication provider: validates kerberos service tickets/SPNEGO tokens
     * non-service: form based authentication
     * service: validate tickets/tokens in SSO authentication (this example also works without that one)
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(kerberosAuthenticationProvider())
                .authenticationProvider(kerberosServiceAuthenticationProvider());
    }

    /**
     * Interface for authentication, manages the authentication providers
     * Necessary to be set in our custom SPNEGO filter
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }

    @Bean
    public KerberosAuthenticationProvider kerberosAuthenticationProvider() {
        KerberosAuthenticationProvider provider = new KerberosAuthenticationProvider();
        SunJaasKerberosClient client = new SunJaasKerberosClient();
        provider.setKerberosClient(client);
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal("HTTP/kdc.bealdung.com@baeldung.com");
        ticketValidator.setKeyTabLocation(new FileSystemResource("/home/nicole/baeldung.keytab"));
        return ticketValidator;
    }

}

