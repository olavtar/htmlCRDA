package com.redhat.ecosystemappeng.snyk;

import java.util.List;

public class Temp {
    private String group;
    private String artifact;
    private String version;
    private List<Temp> dependencies;
    private List<Issue> issues;

    public int countDirectVulnerabilities() {
        return issues.size();
    }
    public int countTransitiveVulnerabilities() {
        int transitive = 0;
        for (Temp dependency : dependencies) {
            transitive += dependency.countDirectVulnerabilities() + dependency.countTransitiveVulnerabilities();
        }
        return transitive;
    }

    public void addDepdendency(Temp mavenPackage) {
        dependencies.add(mavenPackage);
    }
}
