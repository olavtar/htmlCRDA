package com.redhat.ecosystemappeng.snyk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Root {

        public ArrayList<Issue> issues;
        public Map<String, IssuesData> issuesData = new HashMap<>();
        public boolean ok;
        public Org org;
        public String packageManager;

    public ArrayList<Issue> getIssues() {
        return issues;
    }

    public void setIssues(ArrayList<Issue> issues) {
        this.issues = issues;
    }

    public Map<String, IssuesData> getIssuesData() {
        return issuesData;
    }

    public void setIssuesData(Map<String, IssuesData> issuesData) {
        this.issuesData = issuesData;
    }

    public boolean isOk() {
        return ok;
    }

    public void setOk(boolean ok) {
        this.ok = ok;
    }

    public Org getOrg() {
        return org;
    }

    public void setOrg(Org org) {
        this.org = org;
    }

    public String getPackageManager() {
        return packageManager;
    }

    public void setPackageManager(String packageManager) {
        this.packageManager = packageManager;
    }

}
