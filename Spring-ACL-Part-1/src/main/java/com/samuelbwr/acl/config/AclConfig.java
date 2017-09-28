package com.samuelbwr.acl.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.acls.AclPermissionCacheOptimizer;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AclConfig extends GlobalMethodSecurityConfiguration {

    @Autowired
    DataSource dataSource;

    AuditLogger auditLogger = new ConsoleAuditLogger();

    @Bean
    JdbcMutableAclService aclService() {
        return new JdbcMutableAclService( dataSource, lookupStrategy(), aclCache() );
    }

    LookupStrategy lookupStrategy() {
        return new BasicLookupStrategy( dataSource,
                aclCache(), new AclAuthorizationStrategyImpl( new SimpleGrantedAuthority( "ROLE_ADMINISTRATOR" ) ), auditLogger );
    }

    private SpringCacheBasedAclCache aclCache() {
        return new SpringCacheBasedAclCache(
                new ConcurrentMapCache( "cache" ),
                new DefaultPermissionGrantingStrategy( auditLogger ),
                new AclAuthorizationStrategyImpl( new SimpleGrantedAuthority( "ROLE_ACL_ADMIN" ) ) );
    }

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        org.springframework.security.acls.model.AclService service = aclService();
        DefaultMethodSecurityExpressionHandler expressionHandler =
                new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator( new AclPermissionEvaluator( service ) );
        expressionHandler.setPermissionCacheOptimizer( new AclPermissionCacheOptimizer( service ) );
        return expressionHandler;
    }
}
