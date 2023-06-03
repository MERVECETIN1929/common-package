package com.kodlamaio.commonpackage.utils.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@Setter
@Getter
@NoArgsConstructor
public class PaymentRentalRequest extends Payment{
    private double price;
}
