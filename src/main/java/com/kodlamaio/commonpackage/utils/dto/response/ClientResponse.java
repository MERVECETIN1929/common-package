package com.kodlamaio.commonpackage.utils.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ClientResponse {
    private boolean isSuccess;
    private String message;
}
