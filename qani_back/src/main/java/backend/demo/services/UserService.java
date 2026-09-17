package backend.demo.services;
import backend.demo.dto.AddUser;
import backend.demo.dto.AuthData;
import backend.demo.dto.AuthResponse;
import backend.demo.dto.UserDTO;
import backend.demo.entities.Users;
import backend.demo.repositories.UserRepository;
import backend.demo.securityJWT.JwtService;
import backend.demo.util.GeneralUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public Optional<Users> findUser(String username) {
        return userRepository.findByUsername(username);
    }

    public void saveUser(UserDTO userDto) {
        Users user = new Users();
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());
        user.setUsername(userDto.getUsername());
        user.setPassword(userDto.getPassword());

        userRepository.save(user);
    }

    //get-all
    public List<Users> getAllUsers() {
        return userRepository.findAll();
    }

    //sign-up
    public Users addNewUser(AddUser addUser) throws Exception {
        Users user = new Users();
        GeneralUtil.getCopyOf(addUser, user);

        if (addUser.getPassword() == null || addUser.getPassword().isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }

        user.setPassword(passwordEncoder.encode(addUser.getPassword()));

        return userRepository.save(user);
    }
    

    //sign-in
    public AuthResponse signIn(AuthData data) throws Exception {
        Users user = userRepository.findByUsername(data.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("USER_NOT_FOUND"));

        AddUser response = new AddUser();
        Map<String, Object> claims = new HashMap<>();
        String tok = jwtService.generateToken(user);
        GeneralUtil.getCopyOf(user, response);
        return new AuthResponse(tok);
    }

    //delete
    @Transactional
    public boolean deleteUserByUsername(String username) {
        if (!userRepository.existsByUsername(username)) {
            return false;
        }
        userRepository.deleteByUsername(username);
        return true;
    }


}
