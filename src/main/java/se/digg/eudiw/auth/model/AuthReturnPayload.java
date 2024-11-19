package se.digg.eudiw.auth.model;

public class AuthReturnPayload {
    String response;

    public AuthReturnPayload() {
    }

    public AuthReturnPayload(String response) {
        this.response = response;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

}
