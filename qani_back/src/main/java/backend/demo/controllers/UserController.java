package backend.demo.controllers;
import backend.demo.dto.AuthData;
import backend.demo.dto.AuthResponse;
import backend.demo.dto.UserDTO;
import backend.demo.repositories.UserRepository;
import backend.demo.services.UserService;
import backend.demo.entities.Users;
import jakarta.persistence.Access;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/users")
public class UserController {
    private final  UserService userService;

    @Autowired
    private UserRepository userRepository;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(value = "/{username}", method = RequestMethod.GET, produces = {"application/json"})
    public Users getOne(@PathVariable String username) {
        return userService.findUser(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @PostMapping(value = "/signup", produces = {"application/json"})
    public ResponseEntity<String> add(@RequestBody UserDTO request ) throws Exception {
        userService.saveUser(request);
        return ResponseEntity.ok("Signed Up Successfully");
    }

    @PostMapping(value = "/signin", produces = {"application/json"})
    public ResponseEntity<AuthResponse> login(
            @RequestBody AuthData request
    ) throws Exception {
        return ResponseEntity.ok(userService.signIn(request));
    }


    @DeleteMapping(value = "/{username}", produces = {"application/json"})
    @Transactional
    public ResponseEntity<String> deleteUserByUsername(@PathVariable String username) {
            if (!userRepository.existsByUsername(username)) {
                return ResponseEntity.notFound().build();
            }
            userRepository.deleteByUsername(username);
            return ResponseEntity.ok("User: " + username +  " Has Been Deleted Successfully");
    }

    @GetMapping(value = "/all", produces = {"application/json"})
    public List<Users> getAllUsers() {
        return userService.getAllUsers();
    }

    private UserDTO toDTO(Users user) {
        return new UserDTO(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getUsername(),
                user.getPassword()
        );
    }
}
