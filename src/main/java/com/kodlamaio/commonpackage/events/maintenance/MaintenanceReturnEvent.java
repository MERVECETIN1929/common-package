package com.kodlamaio.commonpackage.events.maintenance;


import com.kodlamaio.commonpackage.events.Event;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class MaintenanceReturnEvent implements Event
{
    private UUID carId;
}
