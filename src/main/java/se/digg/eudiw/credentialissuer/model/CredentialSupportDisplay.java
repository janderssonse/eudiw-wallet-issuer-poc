package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialSupportDisplay {
    String name;
    String locale;
    DisplayLogo logo;
    String description;
    String backgroundColor;
    String textColor;

    public CredentialSupportDisplay() {
        this.name = "";
        this.locale = null;
        this.logo = null;
        this.description = null;
        this.backgroundColor = null;
        this.textColor = null;
    }   

    public CredentialSupportDisplay(String name, String locale, DisplayLogo logo, String description, String backgroundColor, String textColor) {
        this.name = name;
        this.locale = locale;
        this.logo = logo;
        this.description = description;
        this.backgroundColor = backgroundColor;
        this.textColor = textColor;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public DisplayLogo getLogo() {
        return logo;
    }

    public void setLogo(DisplayLogo logo) {
        this.logo = logo;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getBackgroundColor() {
        return backgroundColor;
    }

    public void setBackgroundColor(String backgroundColor) {
        this.backgroundColor = backgroundColor;
    }

    public String getTextColor() {
        return textColor;
    }

    public void setTextColor(String textColor) {
        this.textColor = textColor;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((locale == null) ? 0 : locale.hashCode());
        result = prime * result + ((logo == null) ? 0 : logo.hashCode());
        result = prime * result + ((description == null) ? 0 : description.hashCode());
        result = prime * result + ((backgroundColor == null) ? 0 : backgroundColor.hashCode());
        result = prime * result + ((textColor == null) ? 0 : textColor.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CredentialSupportDisplay other = (CredentialSupportDisplay) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (locale == null) {
            if (other.locale != null)
                return false;
        } else if (!locale.equals(other.locale))
            return false;
        if (logo == null) {
            if (other.logo != null)
                return false;
        } else if (!logo.equals(other.logo))
            return false;
        if (description == null) {
            if (other.description != null)
                return false;
        } else if (!description.equals(other.description))
            return false;
        if (backgroundColor == null) {
            if (other.backgroundColor != null)
                return false;
        } else if (!backgroundColor.equals(other.backgroundColor))
            return false;
        if (textColor == null) {
            if (other.textColor != null)
                return false;
        } else if (!textColor.equals(other.textColor))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialSupportDisplay [name=" + name + ", locale=" + locale + ", logo=" + logo + ", description="
                + description + ", backgroundColor=" + backgroundColor + ", textColor=" + textColor + "]";
    }

}


