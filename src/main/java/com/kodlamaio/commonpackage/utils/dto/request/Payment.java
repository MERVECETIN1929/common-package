package com.kodlamaio.commonpackage.utils.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class Payment {
    private String cardNumber;
    private String cvv;
    private String year;
    private String month;
    private String cardHolderName;

}
