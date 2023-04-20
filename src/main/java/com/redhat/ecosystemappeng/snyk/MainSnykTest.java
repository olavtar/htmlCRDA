package com.redhat.ecosystemappeng.snyk;

import com.fasterxml.jackson.databind.ObjectMapper;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.Version;

import java.io.File;
import java.io.FileWriter;
import java.io.Writer;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class MainSnykTest {

    public static void main(String[] args) throws Exception {

        //read json response file data to String
        byte[] snykJsonData = Files.readAllBytes(Paths.get("response.json"));
        byte[] snykJsonRequest = Files.readAllBytes(Paths.get("request.json"));


        //create ObjectMapper instance
        ObjectMapper objectMapper = new ObjectMapper();
        //convert json string to object
        Root root = objectMapper.readValue(snykJsonData, Root.class);
        RequestRoot requestRoot = objectMapper.readValue(snykJsonRequest, RequestRoot.class);

        MavenPackage rootPkg = getRootPackage(requestRoot, root);
        List<MavenPackage> mavenPackageList = getDisplayData(rootPkg);

        // 1. Configure FreeMarker
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);

        // Where do we load the templates from:
        //       cfg.setClassForTemplateLoading(MainSnykTest.class, "/templates");
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        URL url = loader.getResource("templates");
        String path = url.getPath();
        cfg.setDirectoryForTemplateLoading(new File(path));

        // Some other recommended settings:
        cfg.setIncompatibleImprovements(new Version(2, 3, 20));
        cfg.setDefaultEncoding("UTF-8");
        cfg.setLocale(Locale.US);
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

        // 2. Proccess template(s)
        // 2.1. Prepare the template input:

        Map<String, Object> input = new HashMap<String, Object>();
        List<Issue> issues = root.getIssues();
        String securityTitle = "Security Issues";
        String securityDesc = "Dependencies with high common vulnerabilities and exposures (CVE) score.";
        String subTitle = "Dependencies with security issues in your stack";
        String subDescription = "A list of the dependencies affected with common vulnerabilities and exposures (CVE).";
        String insideHeader = "Commonly Known Vulnerabilities";

        //  System.out.println(mavenPackageList);
        input.put("issues", issues);
        input.put("mavenObject", rootPkg);
        input.put("securityDesc", securityDesc);
        input.put("securityTitle", securityTitle);
        input.put("subTitle", subTitle);
        input.put("subDescription", subDescription);
        input.put("insideHeader", insideHeader);

        // 2.2. Get the template
        Template template = cfg.getTemplate("report.ftlh");

        // 2.3. Generate the output

        // Write output to the console
//        Writer consoleWriter = new OutputStreamWriter(System.out);
//        template.process(input, consoleWriter);

        //write output into a file:
        Writer fileWriter = new FileWriter(new File("snykoutput.html"));
        try {
            template.process(input, fileWriter);
        } finally {
            fileWriter.close();
        }

    }

    // For testing
    private static List<MavenPackage> getDisplayData(MavenPackage rootPkg) {
        System.out.println("rootPkg");
        System.out.println(rootPkg.getPkgName());
        List<MavenPackage> packages = rootPkg.getDependencies();
        System.out.println("Packages size: " + packages.size());
        List<MavenPackage> packagesWithVulnerabilities = new ArrayList<MavenPackage>();
        packagesWithVulnerabilities.addAll(packages);
        System.out.println(packagesWithVulnerabilities.size());

        for (MavenPackage aPackage : packages) {
            System.out.println("*** " + aPackage.getPkgName());
            int directVul = aPackage.countDirectVulnerabilities();
            int transitiveVul = aPackage.countTransitiveVulnerabilities();
            System.out.println(" # Direct : " + directVul);
            System.out.println(" # Transitive : " + transitiveVul);
            List<MavenPackage> transVulDep = aPackage.getVulnerableTransitiveDeps();
            System.out.println(" # in the List : " + transVulDep.size());
            if (directVul != 0) {
                IssuesData highestVul = aPackage.getHighestVulnerability();
            }

            if (directVul == 0 && transitiveVul == 0) {
                packagesWithVulnerabilities.remove(aPackage);
            }

            String htmlName = aPackage.getHtmlName();
            System.out.println("hmtlName: " + htmlName);
        }
        return packagesWithVulnerabilities;
    }

    private static MavenPackage getRootPackage(RequestRoot root, Root responseRoot) {

        Map<String, MavenPackage> packages = new HashMap<>();

        // Response data
        Map<String, IssuesData> issuesDataMap = responseRoot.issuesData;
//        System.out.println("IssuesData:");
//        System.out.println(issuesDataMap.size());

        // Request data
        // iterate through pkgs and insert all into map with id as key and info used to create a Maven pkg as value
        for (RequestPkg pkg : root.depGraph.pkgs) {
            MavenPackage mavenPackage = new MavenPackage();
            mavenPackage.setPkgName(pkg.info.name);
            mavenPackage.setPkgVersion(pkg.info.version);
            packages.put(pkg.id, mavenPackage);
        }
        //      System.out.println("Packages size: " + packages.size());
        //iterate through graph Nodes and for each node lookup maven pkg using nodeId
        for (RequestNode node : root.depGraph.graph.nodes) {
            MavenPackage nodePkg = packages.get(node.nodeId);
            ArrayList<RequestDep> nodeDeps = node.getDeps();
            //iterate through deps of Node and for each dep: nodePkg.addDependency(packages.get(deps))
            for (RequestDep dep : nodeDeps) {
                nodePkg.addDependency(packages.get(dep.nodeId));
            }
        }

        //Iterate through Issues
        //For each one, get the corresponding Maven package and issuesData, and addVulnerability to it
        ArrayList<Issue> issues = responseRoot.issues;
        for (Issue issue : issues) {
            String version = issue.pkgVersion;
            String name = issue.pkgName;
            for (Map.Entry<String, MavenPackage> entry : packages.entrySet()) {
                if (entry.getValue().getPkgName().equals(name) && entry.getValue().getPkgVersion().equals(version)) {
                    String key = entry.getKey();
                    MavenPackage mavenPackage = packages.get(key);
                    IssuesData issuesData = issuesDataMap.get(issue.issueId);
                    mavenPackage.addVulnerability(issuesData);
                }
            }
        }
        return packages.get(root.depGraph.graph.rootNodeId);
    }

}
