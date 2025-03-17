package com.rjproj.memberapp.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@Document
public class File {

    @Id
    private String id;
    private String name;
    private String fileUrl;

}
