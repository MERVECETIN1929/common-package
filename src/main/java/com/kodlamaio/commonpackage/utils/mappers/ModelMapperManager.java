package com.kodlamaio.commonpackage.utils.mappers;

import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.modelmapper.internal.bytebuddy.asm.Advice;
import org.modelmapper.spi.MatchingStrategy;
import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;


@AllArgsConstructor
public class ModelMapperManager implements ModelMapperService{
    private ModelMapper mapper;
    @Override
    public ModelMapper forResponse() {
        mapper.getConfiguration().setAmbiguityIgnored(true)
                .setMatchingStrategy(MatchingStrategies.LOOSE);// loose: her alan birbirine uymak zorunda değil
        return mapper;
    }

    @Override
    public ModelMapper forRequest() {
        mapper.getConfiguration().setAmbiguityIgnored(true)
                .setMatchingStrategy(MatchingStrategies.STANDARD);
        return mapper;
    }
}
