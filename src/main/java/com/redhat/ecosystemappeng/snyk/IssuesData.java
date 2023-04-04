package com.redhat.ecosystemappeng.snyk;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Date;

public class IssuesData {

    @JsonProperty("CVSSv3")
    public String cVSSv3;
    public ArrayList<String> credit = new ArrayList<>();
    @JsonIgnore
    public ArrayList<CvssDetail> cvssDetails = new ArrayList<>();
    public double cvssScore;
    public String description;
    public Date disclosureTime;
    public ArrayList<String> fixedIn = new ArrayList<>();
    public String id;
    public Identifiers identifiers;
    public Insights insights;
    public String language;
    public MavenModuleName mavenModuleName;
    public String moduleName;
    public String packageManager;
    public String packageName;
    public boolean proprietary;
    public Semver semver;
    public String severity;
    public String title;

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }


    public IssuesData() {
    }

    public class Semver{
        public ArrayList<String> vulnerable;
    }

    public class Insights{
        public String getTriageAdvice() {
            return triageAdvice;
        }

        public void setTriageAdvice(String triageAdvice) {
            this.triageAdvice = triageAdvice;
        }

        public Insights() {
        }

        public String triageAdvice;
    }

    public class MavenModuleName{
        public String artifactId;
        public String groupId;
    }

    public class Identifiers{
        @JsonProperty("CVE")
        public ArrayList<Object> cVE;
        @JsonProperty("CWE")
        public ArrayList<String> cWE;
        @JsonProperty("GHSA")
        public ArrayList<String> gHSA;
    }
}
