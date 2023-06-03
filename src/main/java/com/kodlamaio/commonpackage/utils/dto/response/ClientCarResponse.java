package com.kodlamaio.commonpackage.utils.dto.response;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ClientCarResponse {
    private UUID id;
    private int modelYear;
    private String plate;
    private String state;
    private double dailyPrice;
    //private String carModelName;
    private String brandName;
    private UUID modelId;
    private String modelName;
    private String modelBrandName;


}
