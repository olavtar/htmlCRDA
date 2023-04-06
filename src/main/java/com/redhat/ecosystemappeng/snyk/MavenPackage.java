package com.redhat.ecosystemappeng.snyk;

import com.fasterxml.jackson.databind.node.ArrayNode;

import java.util.ArrayList;
import java.util.List;

public class MavenPackage {

    private String pkgName;
    private String pkgVersion;
    private List<MavenPackage> dependencies = new ArrayList<>();
    private List<IssuesData> vulnerabilities = new ArrayList<>();

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

    public List<MavenPackage> getDependencies() {
        return dependencies;
    }

    public void setDependencies(List<MavenPackage> dependencies) {
        this.dependencies = dependencies;
    }

    public List<IssuesData> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<IssuesData> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public void addDependency(MavenPackage dependency) {
        dependencies.add(dependency);
    }

    public void addVulnerability(IssuesData issuesData) {
        vulnerabilities.add(issuesData);
    }

    public int countDirectVulnerabilities() {
        return vulnerabilities.size();
    }

    public int countTransitiveVulnerabilities() {
        int transitive = 0;
        for (MavenPackage dependency : dependencies) {
//            System.out.println(dependency.getPkgName());
//            System.out.println(dependency.countDirectVulnerabilities());
            transitive += dependency.countDirectVulnerabilities() + dependency.countTransitiveVulnerabilities();
        }
        return transitive;
    }

    public IssuesData getHighestVulnerability() {
        IssuesData highestVulIssueData = new IssuesData();
        for (IssuesData item : vulnerabilities) {
            if (item.getCvssScore() > highestVulIssueData.getCvssScore()) {
                highestVulIssueData = item;
            }
        }
        return highestVulIssueData;
    }

    public List<MavenPackage> getVulnerableDeps() {
        List<MavenPackage> vulDeps = new ArrayList<MavenPackage>();
        for (MavenPackage dependency : dependencies) {
            System.out.println(dependency.getPkgName());
            System.out.println(dependency.countDirectVulnerabilities());
            if (dependency.countDirectVulnerabilities() == 0 && dependency.countTransitiveVulnerabilities() == 0) {
                continue;
            }
            if (dependency.countDirectVulnerabilities() > 0) {
                vulDeps.add(dependency);
            }
            if (dependency.countTransitiveVulnerabilities() > 0) {
                vulDeps.addAll(dependency.getVulnerableDeps());
            }
        }
        return vulDeps;
    }
}
