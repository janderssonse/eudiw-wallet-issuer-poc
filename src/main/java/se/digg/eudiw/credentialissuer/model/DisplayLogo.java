package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class DisplayLogo {
    String url;
    String altText;

    public DisplayLogo() {
        this.url = null;
        this.altText = null;
    }

    public DisplayLogo(String url, String altText) {
        this.url = url;
        this.altText = altText;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getAltText() {
        return altText;
    }

    public void setAltText(String altText) {
        this.altText = altText;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((url == null) ? 0 : url.hashCode());
        result = prime * result + ((altText == null) ? 0 : altText.hashCode());
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
        DisplayLogo other = (DisplayLogo) obj;
        if (url == null) {
            if (other.url != null)
                return false;
        } else if (!url.equals(other.url))
            return false;
        if (altText == null) {
            if (other.altText != null)
                return false;
        } else if (!altText.equals(other.altText))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "DisplayLogo [url=" + url + ", altText=" + altText + "]";
    }

}
