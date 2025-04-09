package com.example.bookstore;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.http.*;
import org.springframework.security.core.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.*;
import org.springframework.security.crypto.password.*;
import org.springframework.security.web.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.persistence.*;
import javax.servlet.FilterChain;
import javax.servlet.http.*;
import javax.validation.constraints.*;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
public class BookstoreApplication {
    public static void main(String[] args) {
        SpringApplication.run(BookstoreApplication.class, args);
    }

    // ENTITIES
    @Entity
    class User {
        @Id @GeneratedValue private Long id;
        @Column(unique = true) @NotBlank private String email;
        @NotBlank private String password;
    }

    @Entity
    class Book {
        @Id @GeneratedValue private Long id;
        @NotBlank private String title;
        @NotBlank private String author;
        @NotBlank private String category;
        private double price;
        private double rating;
        private String publishedDate;
    }

    // REPOSITORIES 
    interface UserRepository extends JpaRepository<User, Long> {
        Optional<User> findByEmail(String email);
    }

    interface BookRepository extends JpaRepository<Book, Long> {
        List<Book> findByAuthorContainingIgnoreCase(String author);
        List<Book> findByCategoryContainingIgnoreCase(String category);
        List<Book> findByRatingGreaterThanEqual(double rating);
        List<Book> findByTitleContainingIgnoreCase(String title);
    }

    // DTOs
    record AuthRequest(String email, String password) {}
    record AuthResponse(String token) {}
    record BookDTO(
            @NotBlank String title,
            @NotBlank String category,
            @NotBlank String authorizeString,
            double price,
            double rating,
            String publishedDates
    ) {}

    // JWT UTILS
    @Component
    class JwtUtil {
        private final String SECRET = "mysecretkey123";
        public String generateToken(String username) {
            return Base64.getEncoder().encodeToString((username + ":" + SECRET).getBytes());
        }

        public String extractUsername(String token) {
            try {
                String decoded = new String(Base64.getDecoder().decode(token));
                if (decoded.endsWith(":" + SECRET)) {
                    return decoded.split(":")[0];
                }
            } catch (Exception ignored) {}
            return null;
        }
    }

    // SECURITY CONFIG
    @Configuration
    class SecurityConfig {
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
            http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeHttpRequests()
                    .requestMatchers("/auth/**").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
            return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public UserDetailsService userDetailsService(UserRepository repo) {
            return email -> repo.findByEmail(email)
                    .map(user -> User.builder()
                            .username(user.email)
                            .password(user.password)
                            .roles("USER")
                            .build())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        }

        @Bean
        public AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder encoder, UserDetailsService uds)
                throws Exception {
            return http.getSharedObject(AuthenticationManagerBuilder.class)
                    .userDetailsService(uds)
                    .passwordEncoder(encoder)
                    .and()
                    .build();
        }
    }

   
        @PostMapping("/login")
        public ResponseEntity<?> login(@RequestBody AuthRequest req) {
            try {
                authManager.authenticate(new UsernamePasswordAuthenticationToken(req.email(), req.password()));
                String token = jwtUtil.generateToken(req.email());
                return ResponseEntity.ok(new AuthResponse(token));
            } catch (AuthenticationException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
            }
        }
    }

    @RestController
    @RequestMapping("/books")
    class BookController {
        private final BookRepository repo;

        BookController(BookRepository repo) {
            this.repo = repo;
        }

        @PostMapping
        public ResponseEntity<Book> create(@RequestBody BookDTO dto) {
            Book book = new Book();
            book.title = dto.title();
            book.author = dto.author();
            book.category = dto.category();
            book.price = dto.price();
            book.rating = dto.rating();
            book.publishedDate = dto.publishedDate();
            return ResponseEntity.ok(repo.save(book));
        }

        @GetMapping
        public List<Book> getAll(
                @RequestParam(required = false) String author,
                @RequestParam(required = false) String category,
                @RequestParam(required = false) Double rating,
                @RequestParam(required = false) String title
        ) {
            if (author != null) return repo.findByAuthorContainingIgnoreCase(author);
            if (category != null) return repo.findByCategoryContainingIgnoreCase(category);
            if (rating != null) return repo.findByRatingGreaterThanEqual(rating);
            if (title != null) return repo.findByTitleContainingIgnoreCase(title);
            return repo.findAll();
        }

        @GetMapping("/{id}")
        public ResponseEntity<?> get(@PathVariable Long id) {
            return repo.findById(id)
                    .<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("Book not found"));
        }

        @PutMapping("/{id}")
        public ResponseEntity<?> update(@PathVariable Long id, @RequestBody BookDTO dto) {
            return repo.findById(id).map(book -> {
                book.title = dto.title();
                book.author = dto.author();
                book.category = dto.category();
                book.price = dto.price();
                book.rating = dto.rating();
                book.publishedDate = dto.publishedDate();
                return ResponseEntity.ok(repo.save(book));
            }).orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("Book not found"));
        }

        @DeleteMapping("/{id}")
        public ResponseEntity<?> delete(@PathVariable Long id) {
            if (!repo.existsById(id)) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Book not found");
            repo.deleteById(id);
            return ResponseEntity.ok("Deleted");
        }
}
