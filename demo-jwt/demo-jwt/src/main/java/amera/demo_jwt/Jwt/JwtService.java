package amera.demo_jwt.Jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    // TODO.- Definición de una clave secreta utilizada para firmar los tokens JWT
    private static final String SECRET_KEY = "586E3272357538782F413F44284728486250655368566B597033733676397924";

    // TODO.- Método público para obtener un token basado en los detalles del
    // usuario
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    // TODO.- Método privado que genera un token JWT utilizando reclamaciones
    // adicionales y detalles del usuario
    private String getToken(Map<String, Object> extraClaims, UserDetails user) {
        return Jwts.builder()
                .setClaims(extraClaims) // Añade las reclamaciones adicionales al token
                .setSubject(user.getUsername()) // Establece el sujeto del token (nombre de usuario)
                .setIssuedAt(new Date(System.currentTimeMillis())) // Establece la fecha y hora en que se emite el token
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)) // Establece la fecha de
                                                                                           // expiración del token (24
                                                                                           // horas a partir de la
                                                                                           // emisión)
                .signWith(getKey(), SignatureAlgorithm.HS256) // Firma el token con la clave secreta usando el algoritmo
                                                              // HS256
                .compact(); // Compacta el JWT en su forma final
    }

    // TODO .- Método privado que decodifica la clave secreta y la convierte en una
    // clave de firma HMAC
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // Decodifica la clave secreta de su forma base64
        return Keys.hmacShaKeyFor(keyBytes); // Crea una clave HMAC a partir de los bytes decodificados
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername())&& !isTokenExpired(token));
    }

    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    private Claims getAllclaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllclaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }

}
