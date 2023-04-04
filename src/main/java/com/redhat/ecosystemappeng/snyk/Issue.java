package com.redhat.ecosystemappeng.snyk;

public class Issue {

    public FixInfo fixInfo;
    public String issueId;
    public String pkgName;
    public String pkgVersion;

    @Override
    public String toString() {
        return "Issue{" +
                "fixInfo=" + fixInfo +
                ", issueId='" + issueId + '\'' +
                ", pkgName='" + pkgName + '\'' +
                ", pkgVersion='" + pkgVersion + '\'' +
                '}';
    }

    public Issue() {
    }

    public FixInfo getFixInfo() {
        return fixInfo;
    }

    public void setFixInfo(FixInfo fixInfo) {
        this.fixInfo = fixInfo;
    }

    public String getIssueId() {
        return issueId;
    }

    public void setIssueId(String issueId) {
        this.issueId = issueId;
    }

    public String getPkgName() {
        return pkgName;
    }

    public void setPkgName(String pkgName) {
        this.pkgName = pkgName;
    }

    public String getPkgVersion() {
        return pkgVersion;
    }

    public void setPkgVersion(String pkgVersion) {
        this.pkgVersion = pkgVersion;
    }

    public class FixInfo{
    }

}
