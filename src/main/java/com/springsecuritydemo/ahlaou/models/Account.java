package com.springsecuritydemo.ahlaou.models;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Data //generate getters and setters
@NoArgsConstructor
@AllArgsConstructor
@ToString
//les annotations help hibernate to create table (mapping)
@Entity  //means this class is for a table in database
@Table(name="accounts") //if we don't give a name it will take the same name as the class name
public class Account {


    @Id // identifiant attribute
    @GeneratedValue(strategy = GenerationType.IDENTITY) //this will increment the id automaticly
    private Long id; //id here is a class not primitive , so we used Long not long

    @Column(name="username", length=255, nullable = false) //give a column name
    private String username;
    @Column(name="password", length=255, nullable = false) //give a column name
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) //only access with setters and getters
    private String password;
    //table for relation between 2 entites
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> accountRoles = new ArrayList<>();





}
