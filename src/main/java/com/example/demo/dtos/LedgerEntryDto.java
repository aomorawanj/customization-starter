package com.example.demo.dtos;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
public class LedgerEntryDto {
    private Long id;
    private String accountName;
    private double amount;
    private String transactionType; 
    private String description;
    private java.util.Date transactionDate;
    private String test;
}
-la
-la
