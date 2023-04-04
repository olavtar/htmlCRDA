package com.redhat.ecosystemappeng.snyk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public void addDependency(MavenPackage dependency){
        dependencies.add(dependency);
    }
    public void addVulnerability(IssuesData issuesData) {
        vulnerabilities.add(issuesData);
    }

//
//    private String severity;
//    private double cvssScore;
//    private String title;
//    private int countDirectDeps;
//    private int countTransitiveDeps;
//    private String issueId;

//    public Map<String, MavenPackage> getReportData(Root root, ArrayList<RequestNode> graphNodes) {
//        // Get the graph with all the main dependencies
//        ArrayList<RequestDep> mainDependencies =graphNodes.get(0).deps;
//        Map<String, MavenPackage> reportList = new HashMap<>();
//        Map<String, IssuesData> issuesDataMap = root.getIssuesData();
//
//        getDirectDependencies(reportList, mainDependencies, issuesDataMap);
//        getTransitiveDependencies(reportList, issuesDataMap, graphNodes);
//
//        return reportList;
//    }


//    private Map<String, MavenPackage> getTransitiveDependencies(Map<String, MavenPackage> reportList, Map<String, IssuesData> issuesDataMap, ArrayList<RequestNode> graphNodes) {
////        System.out.println("size: " + reportList.size());
//        for (Map.Entry<String, MavenPackage> entry : reportList.entrySet()) {
//            String key = entry.getKey();
//            Map<String, MavenPackage> dependencies = new HashMap<>();
//            for (RequestNode item : graphNodes) {
//                String nodeName = item.getNodeId();
//                String[] depName = nodeName.split("@");
//                if (depName[0].equals(key)) {
////                    System.out.println("Key: " + key);
////                    System.out.println("depName: " + depName[0]);
//                    ArrayList<RequestDep> itemDeps = item.getDeps();
//                    if(itemDeps.size() > 0 ) {
//                        for (RequestDep depPackage : itemDeps) {
//                            String packageName = depPackage.nodeId;
////                            System.out.println("packageName: " + packageName);
//                            MavenPackage mavenPackage = getMavenPkgData(issuesDataMap, packageName);
//                            if (mavenPackage.getCountDirectDeps() != 0) {
//                                dependencies.put(mavenPackage.getPkgName(), mavenPackage);
//                            }
//                        }
//                    }
////                    System.out.println("Dependency Size: " + dependencies.size());
//                }
//            }
//        }
//        return reportList;
//    }
//
//    private Map<String, MavenPackage> getDirectDependencies(Map<String, MavenPackage> reportList, ArrayList<RequestDep> mainDependencies, Map<String, IssuesData> issuesDataMap) {
//        ArrayList<String> mainPackageNames  = new ArrayList<String>();
//        int countTransitiveDeps = 0;
//        // Count Direct Dependencies vulnerabilities
//        for (RequestDep depPackage : mainDependencies) {
//            String packageName = depPackage.nodeId;
//            MavenPackage mavenPackage = getMavenPkgData(issuesDataMap, packageName);
//            reportList.put(mavenPackage.getPkgName(), mavenPackage);
//        }
//
//        return reportList;
//    }
//
//    private MavenPackage getMavenPkgData(Map<String, IssuesData> issuesDataMap, String name) {
//
//        String[] split = name.split("@");
//        String depName = split[0];
//        String version = split[1];
//
//        MavenPackage mavenPackage = new MavenPackage();
//        Vulnerability highestVulnerability = new Vulnerability();
//        List<Vulnerability> vulnerabilityList = new ArrayList<>();
//        int countDirectDeps = 0;
//        double higestVulnerabilityScore = 0.0;
//        for (Map.Entry<String, IssuesData> entry : issuesDataMap.entrySet()) {
//            IssuesData issuesData = entry.getValue();
//            if (issuesData.getPackageName().equals(depName)) {
//                countDirectDeps++;
//                Vulnerability vulnerability = getVulnerability(issuesData);
//                double vulnerabilityCvssScore = vulnerability.getCvssScore();
//                if(vulnerabilityCvssScore > higestVulnerabilityScore){
//                    highestVulnerability = vulnerability;
//                    higestVulnerabilityScore = vulnerabilityCvssScore;
//                }
//                vulnerabilityList.add(vulnerability);
//            }
//        }
////        System.out.println(depName + " countDirectDeps: " + countDirectDeps);
//        if(countDirectDeps == 0){
//            mavenPackage.setPkgName(depName);
//            mavenPackage.setVulnerabilities(vulnerabilityList);
//            mavenPackage.setIssueId("-");
//            mavenPackage.setCvssScore(0.0);
//            mavenPackage.setPkgVersion(split[1]);
//            mavenPackage.setCountDirectDeps(countDirectDeps);
//        }
//        else {
//            mavenPackage.setPkgName(depName);
//            mavenPackage.setVulnerabilities(vulnerabilityList);
//            mavenPackage.setIssueId(highestVulnerability.getId());
//            mavenPackage.setCvssScore(highestVulnerability.getCvssScore());
//            mavenPackage.setPkgVersion(version);
//            mavenPackage.setCountDirectDeps(countDirectDeps);
//        }
//        return mavenPackage;
//    }
//
//    private Vulnerability getVulnerability(IssuesData issuesData) {
//
//        Vulnerability vulnerability = new Vulnerability();
//        vulnerability.setId(issuesData.getId());
//        vulnerability.setSeverity(issuesData.getSeverity());
//        vulnerability.setTitle(issuesData.getTitle());
//        vulnerability.setCvssScore(issuesData.getCvssScore());
//
//        return vulnerability;
//
//    }
//
//    public List<Vulnerability> getVulnerabilities() {
//        return vulnerabilities;
//    }
//
//    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
//        this.vulnerabilities = vulnerabilities;
//    }
//
//    public String getTitle() {
//        return title;
//    }
//
//    public void setTitle(String title) {
//        this.title = title;
//    }
//
//    public int getCountDirectDeps() {
//        return countDirectDeps;
//    }
//
//    public void setCountDirectDeps(int countDirectDeps) {
//        this.countDirectDeps = countDirectDeps;
//    }
//
//
//    public MavenPackage() {
//    }
//
//    public String getIssueId() {
//        return issueId;
//    }
//
//    public void setIssueId(String issueId) {
//        this.issueId = issueId;
//    }
//
//    public String getPkgName() {
//        return pkgName;
//    }
//
//    public void setPkgName(String pkgName) {
//        this.pkgName = pkgName;
//    }
//
//    public String getPkgVersion() {
//        return pkgVersion;
//    }
//
//    public void setPkgVersion(String pkgVersion) {
//        this.pkgVersion = pkgVersion;
//    }
//
//    public String getSeverity() {
//        return severity;
//    }
//
//    public void setSeverity(String severity) {
//        this.severity = severity;
//    }
//
//    public double getCvssScore() {
//        return cvssScore;
//    }
//
//    public void setCvssScore(double cvssScore) {
//        this.cvssScore = cvssScore;
//    }
//
//    public int getCountTransitiveDeps() {
//        return countTransitiveDeps;
//    }
//
//    public void setCountTransitiveDeps(int countTransitiveDeps) {
//        this.countTransitiveDeps = countTransitiveDeps;
//    }
//    public List<MavenPackage> getDependencies() {
//        return dependencies;
//    }
//
//    public void setDependencies(List<MavenPackage> dependencies) {
//        this.dependencies = dependencies;
//    }
//
//
//    @Override
//    public String toString() {
//        return "MavenPackage{" +
//                "issueId='" + issueId + '\'' +
//                ", pkgName='" + pkgName + '\'' +
//                ", pkgVersion='" + pkgVersion + '\'' +
//                ", severity='" + severity + '\'' +
//                ", cvssScore=" + cvssScore +
//                ", title='" + title + '\'' +
//                ", vulnerabilities=" + vulnerabilities +
//                ", countDirectDeps=" + countDirectDeps +
//                ", countTransitiveDeps=" + countTransitiveDeps +
//                ", dependencies=" + dependencies +
//                '}';
//    }

}
