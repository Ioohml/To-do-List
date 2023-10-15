package br.com.clinicamariaevalirio.todolist.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.clinicamariaevalirio.todolist.users.IUserRepository;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    public IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        
        // Ver se está vindo da rota de task, antes de tudo, do contrário nada aqui vale
        // Também para não intereferir com o que quer que passe por aqui que não seja do assunto
        var servletPath = request.getServletPath();

        if(servletPath.startsWith("/tasks/")) {
            // Pegar o usuário e senha passados
            var authorization = request.getHeader("Authorization");
            var authEncoded = authorization.substring("Basic".length()).trim();
            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecode);
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // Validar usuário
            var user = this.userRepository.findByUsername(username);
            
            if(user == null) {
                response.sendError(401);
            } else {
                // Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

                if(passwordVerify.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }         
        } else {
            filterChain.doFilter(request, response);
        }
    }
}


// System.out.println("Authorization:");
// System.out.println(authorization);
// System.out.println("\nAuthDecode:");
// System.out.println(authDecode);
// System.out.println("\nAuthString:");
// System.out.println(authString);
// System.out.println("\nUsername:");
// System.out.println(username);
// System.out.println("\nPassword:");
// System.out.println(password);       