package org.adaschool.api.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Calendar;
import java.util.Date;

@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

    private String secret;
    private long expiration;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public Date getExpirationDate() {
        long expirationTimeInMilliseconds = Calendar.getInstance().getTimeInMillis() + expiration;
        return new Date(expirationTimeInMilliseconds);
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    public SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(this.secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}

