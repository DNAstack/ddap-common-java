package com.dnastack.ddap.ic.account.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class IcUserInfo {
    @JsonProperty("ga4gh_passport_v1")
    private List<String> passports;
}
