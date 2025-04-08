Company X Java Style Guide

 Introduction
 This style guide outlines the coding conventions for Java code developed at Company X.
 It's based on standard Java conventions and best practices, with some modifications
 to address specific needs and preferences within our organization.

 Key Principles
 * Readability: Code should be easy to understand for all team members.
 * Maintainability: Code should be easy to modify and extend.
 * Consistency: Adhering to a consistent style across all projects improves collaboration and reduces errors.
 * Performance: While readability is paramount, code should be efficient.

Deviations from Standard Java Conventions (if any - explicitly mention them here)

 ## Line Length
 * Maximum line length: 100 characters (aligning with the Python guide).
     * Modern screens allow for wider lines, improving code readability in many cases.
     * Many common patterns in our codebase, like long strings or URLs, often exceed typical limits.

 ## Indentation
 * Use 4 spaces per indentation level. (Standard Java convention)

 ## Imports
 * Group imports:
     * Standard Java library imports (java.*)
     * Related third-party library imports
     * Local application/library specific imports
 * Fully qualified names or explicit imports: Generally prefer explicit imports for clarity.
 * Import order within groups: Sort alphabetically.

 ## Naming Conventions
 * Variables: Use camelCase starting with a lowercase letter: `userName`, `totalCount`
 * Constants: Use uppercase with underscores: `MAX_VALUE`, `DATABASE_NAME`
 * Methods: Use camelCase starting with a lowercase letter: `calculateTotal()`, `processData()`
 * Classes and Interfaces: Use PascalCase (UpperCamelCase): `UserManager`, `PaymentProcessor`, `UserService`
 * Packages: Use lowercase: `com.companyx.utils`, `com.companyx.data`

 ## Javadoc Comments
 * Use `/** ... */` for all Javadoc comments for classes, interfaces, methods, and fields.
 * First sentence: Concise summary of the element's purpose.
 * For complex methods/classes: Include detailed descriptions of parameters (`@param`),
   return values (`@return`), and exceptions (`@throws`).
 * Follow standard Javadoc conventions.
   ```java
   /**
    * Single-line summary.
    *
    * More detailed description, if necessary.
    *
    * @param param1 The first parameter.
    * @param param2 The second parameter.
    * @return The return value. True for success, False otherwise.
    * @throws IllegalArgumentException If {@code param2} is invalid.
    */
   public boolean myMethod(int param1, String param2) throws IllegalArgumentException {
       // method body here
       return true; // Example return
   }
   ```

 ## Type Hints (Generics)
 * Utilize generics extensively: Generics improve type safety and reduce the need for casting.
 * Be explicit with type parameters.

 ## Comments
 * Write clear and concise comments using `//` for single-line comments and `/* ... */` or
   `/** ... */` for multi-line comments.
 * Explain the "why" behind the code, not just the "what".
 * Comment sparingly: Well-written code should be self-documenting where possible.
 * Use complete sentences for block comments.

// ## Logging
// * Use a standard logging framework: Company X uses [Specify framework, e.g., SLF4j with Logback/Log4j2].
// * Log at appropriate levels: TRACE, DEBUG, INFO, WARN, ERROR
// * Provide context: Include relevant information in log messages to aid debugging.

 ## Error Handling
 * Use specific exception types: Avoid using broad exceptions like `Exception`.
 * Handle exceptions gracefully: Provide informative error messages and avoid program termination.
 * Use `try...catch` blocks: Isolate code that might throw exceptions.
 * Consider using checked vs. unchecked exceptions appropriately.

 Tooling
 * Code formatter: [Specify formatter, e.g., IntelliJ IDEA's built-in formatter, Google Java Format] - Enforces consistent formatting automatically./ * Linter/Static Analysis: [Specify tools, e.g., SonarQube, Checkstyle, SpotBugs] - Identifies potential issues and style violations.

// Example
package com.companyx.auth;

import com.companyx.db.UserDatabase;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Module for user authentication.
 */
public class UserAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(UserAuthentication.class);
    private final UserDatabase userDatabase;

    public UserAuthentication(UserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    /**
     * Hashes a password using SHA-256 with a salt.
     *
     * @param password The password to hash.
     * @return The Base64 encoded salt and hashed password separated by a colon.
     */
    public String hashPassword(String password) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltedPassword = new byte[salt.length + password.getBytes(StandardCharsets.UTF_8).length];
            System.arraycopy(salt, 0, saltedPassword, 0, salt.length);
            System.arraycopy(password.getBytes(StandardCharsets.UTF_8), 0, saltedPassword, salt.length, password.getBytes(StandardCharsets.UTF_8).length);
            byte[] hashedPassword = digest.digest(saltedPassword);
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error hashing password: SHA-256 algorithm not found", e);
            throw new IllegalStateException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Authenticates a user against the database.
     *
     * @param username The user's username.
     * @param password The user's password.
     * @return True if the user is authenticated, False otherwise.
     */
    public boolean authenticateUser(String username, String password) {
        try {
            User user = userDatabase.getUser(username);
            if (user == null) {
                logger.warn("Authentication failed: User not found - {}", username);
                return false;
            }

            String storedHash = user.getPasswordHash();
            String[] parts = storedHash.split(":");
            if (parts.length != 2) {
                logger.error("Invalid password hash format for user - {}", username);
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] hashedPassword = Base64.getDecoder().decode(parts[1]);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] saltedPassword = new byte[salt.length + password.getBytes(StandardCharsets.UTF_8).length];
            System.arraycopy(salt, 0, saltedPassword, 0, salt.length);
            System.arraycopy(password.getBytes(StandardCharsets.UTF_8), 0, saltedPassword, salt.length, password.getBytes(StandardCharsets.UTF_8).length);
            byte[] calculatedHash = digest.digest(saltedPassword);

            if (java.util.Arrays.equals(calculatedHash, hashedPassword)) {
                logger.info("User authenticated successfully - {}", username);
                return true;
            } else {
                logger.warn("Authentication failed: Incorrect password - {}", username);
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error during authentication: SHA-256 algorithm not found", e);
            return false;
        } catch (Exception e) {
            logger.error("An error occurred during authentication: {}", e.getMessage(), e);
            return false;
        }
    }

    // Example User class (assuming it exists in com.companyx.db)
    public static class User {
        private String username;
        private String passwordHash;

        public User(String username, String passwordHash) {
            this.username = username;
            this.passwordHash = passwordHash;
        }

        public String getUsername() {
            return username;
        }

        public String getPasswordHash() {
            return passwordHash;
        }
    }

    // Example UserDatabase interface (assuming it exists in com.companyx.db)
    public interface UserDatabase {
        User getUser(String username);
    }
}
