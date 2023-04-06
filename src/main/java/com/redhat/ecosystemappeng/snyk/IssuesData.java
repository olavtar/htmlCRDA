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

    public String getcVSSv3() {
        return cVSSv3;
    }

    public void setcVSSv3(String cVSSv3) {
        this.cVSSv3 = cVSSv3;
    }

    public ArrayList<String> getCredit() {
        return credit;
    }

    public void setCredit(ArrayList<String> credit) {
        this.credit = credit;
    }

    public ArrayList<CvssDetail> getCvssDetails() {
        return cvssDetails;
    }

    public void setCvssDetails(ArrayList<CvssDetail> cvssDetails) {
        this.cvssDetails = cvssDetails;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Date getDisclosureTime() {
        return disclosureTime;
    }

    public void setDisclosureTime(Date disclosureTime) {
        this.disclosureTime = disclosureTime;
    }

    public ArrayList<String> getFixedIn() {
        return fixedIn;
    }

    public void setFixedIn(ArrayList<String> fixedIn) {
        this.fixedIn = fixedIn;
    }

    public Identifiers getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(Identifiers identifiers) {
        this.identifiers = identifiers;
    }

    public Insights getInsights() {
        return insights;
    }

    public void setInsights(Insights insights) {
        this.insights = insights;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public MavenModuleName getMavenModuleName() {
        return mavenModuleName;
    }

    public void setMavenModuleName(MavenModuleName mavenModuleName) {
        this.mavenModuleName = mavenModuleName;
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getPackageManager() {
        return packageManager;
    }

    public void setPackageManager(String packageManager) {
        this.packageManager = packageManager;
    }

    public boolean isProprietary() {
        return proprietary;
    }

    public void setProprietary(boolean proprietary) {
        this.proprietary = proprietary;
    }

    public Semver getSemver() {
        return semver;
    }

    public void setSemver(Semver semver) {
        this.semver = semver;
    }

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
