package amera.demo_jwt.Auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * Data .- Para construir Getter and Setter
 * Builder.- Sirve para construir objetos de manera limpia
 * @AllArgsConstructor.- Constructores con parametros
 * @NoArgsConstructor .- Constructores sin parametros
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    String username;
    String password;
}
