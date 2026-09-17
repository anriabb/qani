package backend.demo.repositories;

import backend.demo.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByUsername(String username);

    void deleteByUsername(String username);

    boolean existsByUsername(String username);
}
