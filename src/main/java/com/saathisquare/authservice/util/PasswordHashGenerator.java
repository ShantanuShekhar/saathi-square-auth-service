package com.saathisquare.authservice.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Utility class to generate BCrypt password hashes
 * Run this main method to generate a hash for a password
 */
public class PasswordHashGenerator {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // CHANGE THIS PASSWORD TO YOUR DESIRED PASSWORD
        String password = (args.length > 0) ? args[0] : "Shan124";  // Can pass password as argument
        String hashedPassword = encoder.encode(password);
        
        System.out.println("========================================");
        System.out.println("BCrypt Password Hash Generator");
        System.out.println("========================================");
        System.out.println("Original Password: " + password);
        System.out.println("BCrypt Hash: " + hashedPassword);
        System.out.println("========================================");
        System.out.println("\nCopy this hash:");
        System.out.println(hashedPassword);
        System.out.println("\n========================================");
        
        // Verify the hash works
        boolean matches = encoder.matches(password, hashedPassword);
        System.out.println("Verification: " + (matches ? "✓ SUCCESS - Password matches hash" : "✗ FAILED - Password does not match hash"));
        System.out.println("========================================\n");
        
        // Generate a couple more hashes to show they're different (BCrypt generates different hashes each time)
        System.out.println("Additional hash examples (BCrypt generates different hashes each time):");
        for (int i = 0; i < 2; i++) {
            System.out.println(encoder.encode(password));
        }
    }
}

