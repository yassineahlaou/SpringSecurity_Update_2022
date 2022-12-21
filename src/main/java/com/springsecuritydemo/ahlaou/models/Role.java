package com.springsecuritydemo.ahlaou.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;


@Data //generate getters and setters
@NoArgsConstructor
@AllArgsConstructor
@ToString
//les annotations help hibernate to create table (mapping)
@Entity  //means this class is for a table in database
@Table(name="roles") //if we don't give a name it will take the same name as the class name
public class Role {

    @Id // identifiant attribute
    @GeneratedValue(strategy = GenerationType.IDENTITY) //this will increment the id automaticly
    private Long id;
    @Column(name="roleName", length=255, nullable = false) //give a column name
    private String roleName;
}
