/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package jaxb.ri.object;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

@XmlRootElement(name = "book")
@XmlType()
public class Book {
    private Long id;

    /**
     * @return the id
     */
    public Long getId() {
        return id;
    }

    @XmlAttribute
    public void setId(Long id) {
        this.id = id;
    }

//    private String name;
//
//    /**
//     * @return the name
//     */
//    public String getName() {
//        return name;
//    }
//
//    private String author;
//
//    /**
//     * @return the author
//     */
//    public String getAuthor() {
//        return author;
//    }
//
//    private Date date;
//
//    /**
//     * @return the date
//     */
//    public Date getDate() {
//        return date;
//    }
//

//
//    @XmlElement(name = "title")
//    public void setName(String name) {
//        this.name = name;
//    }
//
//    @XmlTransient
//    public void setAuthor(String author) {
//        this.author = author;
//    }
//
//    @XmlTransient
//    public void setDate(Date date) {
//        this.date = date;
//    }

    private XMLGregorianCalendar gDate;

    public XMLGregorianCalendar getgDate() {
        return gDate;
    }

    @XmlElement(name = "gdate")
    public void setgDate(XMLGregorianCalendar gDate) {
        this.gDate = gDate;
    }
}
