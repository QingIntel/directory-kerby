package org.apache.kerby.kerberos.kerb.admin.webserver;

/**
 * Created by qingche1 on 10/18/2016.
 */
public class PrincipalEntry {
    private String principalName;
    private String kdcFlags;
    private String disabled;
    private String locked;
    private String expireTime;
    private String createdTime;

    public PrincipalEntry() { }
    public PrincipalEntry(String principalName, String kdcFlags, String disabled,
                          String locked, String expireTime, String createdTime) {
        this.principalName = principalName;
        this.kdcFlags = kdcFlags;
        this.disabled = disabled;
        this.locked = locked;
        this.expireTime = expireTime;
        this.createdTime = createdTime;
    }

    public void setKdcFlags(String kdcFlags) {
        this.kdcFlags = kdcFlags;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public void setDisabled(String disabled) {
        this.disabled = disabled;
    }

    public void setLocked(String locked) {
        this.locked = locked;
    }

    public void setExpireTime(String expireTime) {
        this.expireTime = expireTime;
    }

    public void setCreatedTime(String createdTime) {
        this.createdTime = createdTime;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public String getKdcFlags() {
        return kdcFlags;
    }

    public String getDisabled() {
        return disabled;
    }

    public String getLocked() {
        return locked;
    }

    public String getExpireTime() {
        return expireTime;
    }

    public String getCreatedTime() {
        return createdTime;
    }
}
